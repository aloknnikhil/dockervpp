package dockervpp

import (
	"dockervpp/bin_api/af_packet"
	"dockervpp/bin_api/interfaces"
	"dockervpp/bin_api/l2"
	"log"
	"net"

	"github.com/vishvananda/netlink"

	"github.com/docker/libnetwork/netutils"

	"git.fd.io/govpp.git/api"
	"github.com/pkg/errors"
)

type vppinterface struct {
	api.Channel
	swifidx interfaces.InterfaceIndex
	address net.IP
	subnet  *net.IPNet
	mac     net.HardwareAddr
}

type vppbridge struct {
	api.Channel
	ID       uint32
	gateway  *vppinterface
	segments []*vppinterface
}

func (b *vppbridge) Close() (err error) {
	// Delete Gateway
	if err = b.DeleteGateway(); err != nil {
		err = errors.Wrap(err, "vppbridge.DeleteGateway()")
		return
	}

	// TODO: Delete Each Segment
	return
}

// mac - Optional
func (b *vppbridge) CreateGateway(address net.IP, subnet *net.IPNet, mac net.HardwareAddr) (err error) {
	if b.Channel == nil {
		err = errors.New("No VPP client session")
		return
	}

	if address == nil {
		err = errors.New("Invalid gateway IP address")
		return
	}

	if mac == nil {
		mac = netutils.GenerateMACFromIP(address)
	}

	log.Printf("Creating gateway with IP: %s, Mac: %s\n", address, mac)

	// Step 1: Create Loopback Interface
	if b.gateway, err = createLoopbackInterface(b.Channel, mac); err != nil {
		err = errors.Wrap(err, "createLoopbackInterface()")
		return
	}

	// Step 2: Add loopback to vppbridge
	if err = b.AddInterface(b.gateway, l2.L2_API_PORT_TYPE_BVI); err != nil {
		err = errors.Wrap(err, "b.AddInterface()")
		return
	}

	// Step 3: Set interface state up
	if err = b.gateway.Up(); err != nil {
		err = errors.Wrap(err, "gateway.Up()")
		return
	}

	// Step 4: Set interface address
	if err = b.gateway.SetAddress(address, subnet); err != nil {
		err = errors.Wrapf(err, "gateway.SetAddress(%s)", address)
		return
	}
	return
}

func (b *vppbridge) DeleteGateway() (err error) {
	if b.Channel == nil {
		err = errors.New("No VPP client session")
		return
	}

	if b.gateway == nil {
		err = errors.New("No active gateway")
		return
	}

	request := &interfaces.DeleteLoopback{
		SwIfIndex: uint32(b.gateway.swifidx),
	}

	// Dispatch request
	ctx := b.Channel.SendRequest(request)
	response := &interfaces.DeleteLoopbackReply{}
	if err = ctx.ReceiveReply(response); err != nil {
		err = errors.Wrap(err, "ctx.ReceiveReply()")
		return
	}

	if response.Retval != 0 {
		err = errors.Errorf("DeleteLoopbackReply: %d error", response.Retval)
		return
	}
	b.gateway = nil
	return
}

func (b *vppbridge) AddInterface(vppinterface *vppinterface, portType l2.L2PortType) (err error) {
	request := &l2.SwInterfaceSetL2Bridge{
		RxSwIfIndex: uint32(vppinterface.swifidx),
		BdID:        b.ID,
		PortType:    portType,
		Enable:      1,
		Shg:         0,
	}

	// Dispatch request
	ctx := b.Channel.SendRequest(request)
	response := &l2.SwInterfaceSetL2BridgeReply{}
	if err = ctx.ReceiveReply(response); err != nil {
		err = errors.Wrap(err, "ctx.ReceiveReply()")
		return
	}
	if response.Retval != 0 {
		err = errors.Errorf("AddLoopBackReply: %d error", response.Retval)
		return
	}

	// Cache vppbridge segment
	b.segments = append(b.segments, vppinterface)
	return
}

func (vppinterface *vppinterface) Up() (err error) {
	uploop := &interfaces.SwInterfaceSetFlags{
		SwIfIndex:   uint32(vppinterface.swifidx),
		AdminUpDown: 1,
	}

	// Dispatch request
	ctx := vppinterface.Channel.SendRequest(uploop)
	uploopreply := &interfaces.SwInterfaceSetFlagsReply{}
	if err = ctx.ReceiveReply(uploopreply); err != nil {
		err = errors.Wrap(err, "ctx.ReceiveReply()")
		return
	}
	if uploopreply.Retval != 0 {
		err = errors.Errorf("UpLoopbackReply: %d error", uploopreply.Retval)
		return
	}
	return
}

func createLoopbackInterface(api api.Channel, mac net.HardwareAddr) (intfc *vppinterface, err error) {
	createloop := &interfaces.CreateLoopback{
		MacAddress: mac,
	}

	// Dispatch request
	ctx := api.SendRequest(createloop)
	createloopreply := &interfaces.CreateLoopbackReply{}
	if err = ctx.ReceiveReply(createloopreply); err != nil {
		err = errors.Wrap(err, "ctx.ReceiveReply()")
		return
	}
	if createloopreply.Retval != 0 {
		err = errors.Errorf("CreateLoopbackReply: %d error", createloopreply.Retval)
		return
	}
	intfc = &vppinterface{
		Channel: api,
		swifidx: interfaces.InterfaceIndex(createloopreply.SwIfIndex),
		mac:     mac,
	}
	return
}

func createHostInterface(api api.Channel, veth *netlink.Veth) (intfc *vppinterface, err error) {
	if len(veth.Attrs().Name) > 64 {
		err = errors.New("Interface name cannot be > 64 characters")
		return
	}
	request := &af_packet.AfPacketCreate{
		HostIfName:      []byte(veth.Attrs().Name),
		HwAddr:          veth.HardwareAddr,
		UseRandomHwAddr: 0,
	}
	ctx := api.SendRequest(request)
	response := &af_packet.AfPacketCreateReply{}
	if err = ctx.ReceiveReply(response); err != nil {
		err = errors.Wrap(err, "ctx.ReceiveReply()")
		return
	}
	if response.Retval != 0 {
		err = errors.Errorf("AF_PACKETCreate: %d error", response.Retval)
		return
	}
	intfc = &vppinterface{
		Channel: api,
		swifidx: interfaces.InterfaceIndex(response.SwIfIndex),
		mac:     veth.HardwareAddr,
	}
	return
}

func (vppinterface *vppinterface) SetAddress(address net.IP, subnet *net.IPNet) (err error) {
	setaddress := &interfaces.SwInterfaceAddDelAddress{
		SwIfIndex:     uint32(vppinterface.swifidx),
		IsAdd:         1,
		IsIPv6:        0,
		DelAll:        0,
		AddressLength: 24,
		Address:       address.To4(),
	}

	// Dispatch request
	ctx := vppinterface.Channel.SendRequest(setaddress)
	setaddressreply := &interfaces.SwInterfaceAddDelAddressReply{}
	if err = ctx.ReceiveReply(setaddressreply); err != nil {
		err = errors.Wrap(err, "ctx.ReceiveReply()")
		return
	}
	if setaddressreply.Retval != 0 {
		err = errors.Errorf("SetAddressReply: %d error", setaddressreply.Retval)
		return
	}
	vppinterface.address = address
	vppinterface.subnet = subnet
	return
}
