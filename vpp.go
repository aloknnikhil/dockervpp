package dockervpp

import (
	"dockervpp/bin_api/interfaces"
	"dockervpp/bin_api/l2"
	"log"
	"math"
	"net"

	"github.com/docker/libnetwork/netutils"

	"git.fd.io/govpp.git/api"
	"github.com/pkg/errors"
)

const (
	macPrefix = "af:be:cd:00:"
)

type bridge struct {
	api.Channel
	ID       uint32
	gateway  interfaces.InterfaceIndex
	segments []interfaces.InterfaceIndex
}

func (b *bridge) Close() (err error) {
	// Delete Gateway
	if err = b.DeleteGateway(); err != nil {
		err = errors.Wrap(err, "bridge.DeleteGateway()")
		return
	}

	// TODO: Delete Each Segment
	return
}

// mac - Optional
func (b *bridge) CreateGateway(address net.IP, mac net.HardwareAddr) (err error) {
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
	createloop := &interfaces.CreateLoopback{
		MacAddress: mac,
	}

	// Dispatch request
	ctx := b.Channel.SendRequest(createloop)
	createloopreply := &interfaces.CreateLoopbackReply{}
	if err = ctx.ReceiveReply(createloopreply); err != nil {
		err = errors.Wrap(err, "ctx.ReceiveReply()")
		return
	}
	if createloopreply.Retval != 0 {
		err = errors.Errorf("CreateLoopbackReply: %d error", createloopreply.Retval)
		return
	}
	b.gateway = interfaces.InterfaceIndex(createloopreply.SwIfIndex)

	// Step 2: Add loopback to bridge
	addloop := &l2.SwInterfaceSetL2Bridge{
		RxSwIfIndex: uint32(b.gateway),
		BdID:        b.ID,
		PortType:    l2.L2_API_PORT_TYPE_BVI,
		Enable:      1,
		Shg:         0,
	}

	// Dispatch request
	ctx = b.Channel.SendRequest(addloop)
	addloopreply := &l2.SwInterfaceSetL2BridgeReply{}
	if err = ctx.ReceiveReply(addloopreply); err != nil {
		err = errors.Wrap(err, "ctx.ReceiveReply()")
		return
	}
	if addloopreply.Retval != 0 {
		err = errors.Errorf("AddLoopBackReply: %d error", addloopreply.Retval)
		return
	}

	// Step 3: Set interface state up
	uploop := &interfaces.SwInterfaceSetFlags{
		SwIfIndex:   uint32(b.gateway),
		AdminUpDown: 1,
	}

	// Dispatch request
	ctx = b.Channel.SendRequest(uploop)
	uploopreply := &interfaces.SwInterfaceSetFlagsReply{}
	if err = ctx.ReceiveReply(uploopreply); err != nil {
		err = errors.Wrap(err, "ctx.ReceiveReply()")
		return
	}
	if uploopreply.Retval != 0 {
		err = errors.Errorf("UpLoopbackReply: %d error", uploopreply.Retval)
		return
	}

	// Step 4: Set interface address
	setaddress := &interfaces.SwInterfaceAddDelAddress{
		SwIfIndex:     uint32(b.gateway),
		IsAdd:         1,
		IsIPv6:        0,
		DelAll:        0,
		AddressLength: 24,
		Address:       address.To4(),
	}

	// Dispatch request
	ctx = b.Channel.SendRequest(setaddress)
	setaddressreply := &interfaces.SwInterfaceAddDelAddressReply{}
	if err = ctx.ReceiveReply(setaddressreply); err != nil {
		err = errors.Wrap(err, "ctx.ReceiveReply()")
		return
	}
	if setaddressreply.Retval != 0 {
		err = errors.Errorf("SetAddressReply: %d error", uploopreply.Retval)
		return
	}
	return
}

func (b *bridge) DeleteGateway() (err error) {
	if b.Channel == nil {
		err = errors.New("No VPP client session")
		return
	}

	if b.gateway == math.MaxUint32 {
		err = errors.New("No active gateway")
		return
	}

	request := &interfaces.DeleteLoopback{
		SwIfIndex: uint32(b.gateway),
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
	b.gateway = math.MaxUint32
	return
}

func (b *bridge) AddSegment(intidx interfaces.InterfaceIndex) (err error) {
	if b.Channel == nil {
		err = errors.New("No VPP client session")
		return
	}

	return
}
