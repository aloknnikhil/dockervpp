package dockervpp

import (
	"encoding/json"
	"log"
	"net"
	"os/user"
	"strconv"
	"sync"
	"syscall"

	"github.com/vishvananda/netns"

	"git.fd.io/govpp.git/api"

	"github.com/docker/libkv"

	"github.com/FDio/govpp"

	"git.fd.io/govpp.git/core"
	"github.com/docker/docker/pkg/plugins"
	"github.com/docker/go-plugins-helpers/network"
	"github.com/docker/libkv/store"
	"github.com/docker/libkv/store/boltdb"
	"github.com/docker/libnetwork/netlabel"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
)

// Configuration for the default store path & VPP API socket path
const (
	KVStorePath string = "/var/lib/narf/vpp/driver.db"
	VPPAPISock  string = "/var/run/vpp/vpp-api.sock"
)

// Client to interact with VPP
var Client driver

type driver struct {
	sync.Once
	sync.WaitGroup
	network string
	vppcnx  *core.Connection
	vppapi  api.Channel
	docker  *plugins.Client
	nlink   *netlink.Handle
	store   store.Store
}

func init() {
	boltdb.Register()
}

func (d *driver) Run(username string) (err error) {
	d.Do(func() {
		// Init store
		if d.store, err = libkv.NewStore(
			store.BOLTDB,
			[]string{
				KVStorePath,
			},
			// TODO: Shard data that is not dependent
			&store.Config{
				Bucket: "config",
			},
		); err != nil {
			err = errors.Wrap(err, "libkv.NewStore")
			return
		}

		// Connect to VPP
		if d.vppcnx, err = govpp.Connect(VPPAPISock); err != nil {
			err = errors.Wrap(err, "govpp.Connect()")
			return
		}
		if d.vppapi, err = d.vppcnx.NewAPIChannel(); err != nil {
			err = errors.Wrap(err, "vpp.NewAPIChannel()")
			return
		}

		// Setup Netlink handle
		if d.nlink, err = netlink.NewHandleAt(netns.None(), syscall.NETLINK_ROUTE); err != nil {
			err = errors.Wrap(err, "netlink.NewHandleAt()")
			return
		}

		// Setup plugin socket
		var group *user.Group
		if group, err = user.LookupGroup(username); err != nil {
			err = errors.Wrapf(err, "user.LookupGroup(%s)", username)
			return
		}
		var gid int
		if gid, err = strconv.Atoi(group.Gid); err != nil {
			err = errors.Wrap(err, "strconv.Atoi()")
			return
		}
		d.Add(1)
		defer d.Done()

		if err = network.NewHandler(d).ServeUnix("vpp", gid); err != nil {
			err = errors.Wrap(err, "network.NewHandler().ServeUnix")
			return
		}
	})

	return
}

func (d *driver) AllocateNetwork(
	request *network.AllocateNetworkRequest,
) (response *network.AllocateNetworkResponse, err error) {
	log.Println("AllocateNetwork")
	//err = &driverapi.ErrNotImplemented{}
	return
}

func (d *driver) CreateEndpoint(
	request *network.CreateEndpointRequest,
) (response *network.CreateEndpointResponse, err error) {
	log.Printf("CreateEndpoint - %+v\n", request)

	if request.Interface == nil {
		err = errors.Wrap(err, "Invalid interface specified")
		return
	}

	// Create VETH pair for end-point
	vETH := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "VPP" + request.NetworkID[:4]},
		PeerName:  "VETH" + request.NetworkID[:4],
	}

	if err = d.nlink.LinkAdd(vETH); err != nil {
		err = errors.Wrap(err, "netlink.LinkAdd()")
		return
	}

	// Set MAC address of the VETH (peer-side)
	var peer netlink.Link
	if peer, err = d.nlink.LinkByName(vETH.PeerName); err != nil {
		err = errors.Wrap(err, "d.nlink.LinkByName()")
		return
	}

	response = &network.CreateEndpointResponse{}

	if len(request.Interface.MacAddress) != 0 {
		var mac net.HardwareAddr
		if mac, err = net.ParseMAC(request.Interface.MacAddress); err != nil {
			err = errors.Wrapf(err, "net.ParseMAC(%s)", request.Interface.MacAddress)
			return
		}

		// Override MAC address for the peer
		if err = d.nlink.LinkSetHardwareAddr(peer, mac); err != nil {
			err = errors.Wrap(err, "d.nlink.LinkSetHardwareAddr()")
			return
		}
	} else {
		response.Interface = &network.EndpointInterface{
			MacAddress: peer.Attrs().HardwareAddr.String(),
		}
	}

	// Set IP address
	if len(request.Interface.Address) != 0 {
		var ip4 *netlink.Addr
		if ip4, err = netlink.ParseAddr(request.Interface.Address); err != nil {
			err = errors.Wrapf(err, "netlink.ParseAddr(%s)", request.Interface.Address)
			return
		}
		if err = d.nlink.AddrAdd(peer, ip4); err != nil {
			err = errors.Wrapf(err, "netlink.AddrAdd(%s)", request.Interface.Address)
			return
		}
	}
	if len(request.Interface.AddressIPv6) != 0 {
		var ip6 *netlink.Addr
		if ip6, err = netlink.ParseAddr(request.Interface.AddressIPv6); err != nil {
			err = errors.Wrapf(err, "netlink.ParseAddr(%s)", request.Interface.AddressIPv6)
			return
		}
		if err = d.nlink.AddrAdd(peer, ip6); err != nil {
			err = errors.Wrapf(err, "netlink.AddrAdd(%s)", request.Interface.AddressIPv6)
			return
		}
	}

	log.Printf("Created Endpoint - %+v\n", peer)

	//err = &driverapi.ErrNotImplemented{}
	return
}

func (d *driver) CreateNetwork(
	request *network.CreateNetworkRequest,
) (err error) {
	log.Printf("CreateNetwork - %+v\n", request)

	// Get Network ID
	networkID := request.NetworkID
	if len(request.Options) == 0 {
		err = errors.New("CreateNetwork: No create options specified")
		log.Println(err.Error())
		return
	}

	// Check if IPv6 network
	isIPV6 := false
	if val, ok := request.Options[netlabel.Prefix+netlabel.EnableIPv6]; ok {
		if isIPV6, ok = val.(bool); !ok {
			err = errors.Errorf("CreateNetwork: Invalid value for %s", netlabel.Prefix+netlabel.EnableIPv6)
			log.Println(err.Error())
			return
		}
	}

	// If IPv6, verify there's atleast 1 subnet specified
	var ip6gateway net.IP
	var ip6pool *net.IPNet
	if isIPV6 {
		if len(request.IPv6Data) == 0 {
			err = errors.New("CreateNetwork: IPv6 requested but no subnet specified")
			log.Println(err.Error())
			return
		}
		if ip6gateway, _, err = net.ParseCIDR(request.IPv6Data[0].Gateway); err != nil {
			err = errors.Errorf("CreateNetwork: Could not parse IPv6 Gateway: %s", err.Error())
			log.Println(err.Error())
			return
		}
		if _, ip6pool, err = net.ParseCIDR(request.IPv6Data[0].Pool); err != nil {
			err = errors.Errorf("CreateNetwork: Could not parse IPv6 Pool: %s", err.Error())
			log.Println(err.Error())
			return
		}
	}

	// If IPv4, verify there's atleast 1 subnet specified
	var ip4gateway net.IP
	var ip4pool *net.IPNet
	if len(request.IPv4Data) == 0 {
		if !isIPV6 {
			err = errors.New("No IPv4/6 subnets specified")
			log.Println(err.Error())
			return
		}
	} else {
		if ip4gateway, _, err = net.ParseCIDR(request.IPv4Data[0].Gateway); err != nil {
			err = errors.Errorf("CreateNetwork: Could not parse IPv4 Gateway: %s", err.Error())
			log.Println(err.Error())
			return
		}
		if _, ip4pool, err = net.ParseCIDR(request.IPv4Data[0].Pool); err != nil {
			err = errors.Errorf("CreateNetwork: Could not parse IPv4 Pool: %s", err.Error())
			log.Println(err.Error())
			return
		}
	}

	// Marshall & store
	// TODO: Delete if VPP's state is dependent on the driver's state
	var value json.RawMessage
	if value, err = json.Marshal(request); err != nil {
		err = errors.Wrap(err, "json.Marshal()")
		return
	}

	success := false
	if success, _, err = d.store.AtomicPut(networkID, value, nil, nil); err != nil {
		err = errors.Wrap(err, "store.AtomicPut()")
		return
	}

	if !success {
		err = errors.Errorf("Could not create new network in store %s", networkID)
		return
	}

	log.Printf("Stored network configuration - ID:%s; IPv4 Gateway: %+v; IPv4 Pool: %+v; IPv6 Gateway: %+v, IPv6 Pool: %+v", networkID, ip4gateway, ip4pool, ip6gateway, ip6pool)
	return
}

func (d *driver) DeleteEndpoint(
	request *network.DeleteEndpointRequest,
) (err error) {
	log.Println("DeleteEndpoint")

	vETH := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "VPP" + request.NetworkID[:4]},
		PeerName:  "VETH" + request.NetworkID[:4],
	}

	var peer netlink.Link
	if peer, err = d.nlink.LinkByName(vETH.PeerName); err != nil {
		err = errors.Wrap(err, "netlink.LinkByName()")
		return
	}

	if err = d.nlink.LinkDel(peer); err != nil {
		err = errors.Wrapf(err, "netlink.LinkDel(%+v)", peer)
		return
	}

	log.Printf("Endpoint - %+v deleted\n", peer)
	return
}

func (d *driver) DeleteNetwork(
	request *network.DeleteNetworkRequest,
) (err error) {
	log.Println("DeleteNetwork")
	networkID := request.NetworkID

	// Check if the network exists
	var kv *store.KVPair
	if kv, err = d.store.Get(networkID); err != nil {
		if err == store.ErrKeyNotFound {
			err = errors.Errorf("Network w/ ID: %s not found", networkID)
			log.Println(err.Error())
			return
		}
		err = errors.Wrap(err, "d.store.Get()")
		log.Println(err.Error())
		return
	}

	// TODO: Validate
	var ok bool
	if ok, err = d.store.AtomicDelete(networkID, kv); err != nil {
		err = errors.Wrap(err, "d.store.AtomicDelete()")
		log.Println(err.Error())
		return
	}

	if !ok {
		err = errors.Errorf("Failed to delete network %s. Try again later", networkID)
		log.Println(err.Error())
		return
	}
	return
}

func (d *driver) DiscoverDelete(
	notification *network.DiscoveryNotification,
) (err error) {
	log.Println("DiscoverDelete")
	//err = &driverapi.ErrNotImplemented{}
	return
}

func (d *driver) DiscoverNew(
	notification *network.DiscoveryNotification,
) (err error) {
	log.Println("DiscoverNew")
	//err = &driverapi.ErrNotImplemented{}
	return
}

func (d *driver) EndpointInfo(
	request *network.InfoRequest,
) (response *network.InfoResponse, err error) {
	log.Println("EndpointInfo")
	//err = &driverapi.ErrNotImplemented{}
	return
}

func (d *driver) FreeNetwork(
	request *network.FreeNetworkRequest,
) (err error) {
	log.Println("EndpointInfo")
	//err = &driverapi.ErrNotImplemented{}
	return
}

func (d *driver) GetCapabilities() (
	response *network.CapabilitiesResponse, err error,
) {
	log.Println("GetCapabilities")
	response = &network.CapabilitiesResponse{Scope: network.LocalScope, ConnectivityScope: network.GlobalScope}
	return
}

func (d *driver) Join(
	request *network.JoinRequest,
) (response *network.JoinResponse, err error) {
	log.Println("Join")

	vETH := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "VPP" + request.NetworkID[:4]},
		PeerName:  "VETH" + request.NetworkID[:4],
	}

	response = &network.JoinResponse{
		InterfaceName: network.InterfaceName{
			SrcName:   vETH.PeerName,
			DstPrefix: "narf",
		},
	}
	return
}

func (d *driver) Leave(
	request *network.LeaveRequest,
) (err error) {
	log.Println("Leave")
	//err = &driverapi.ErrNotImplemented{}
	return
}

func (d *driver) ProgramExternalConnectivity(
	request *network.ProgramExternalConnectivityRequest,
) (err error) {
	log.Println("ProgramExternalConnectivity")
	//err = &driverapi.ErrNotImplemented{}
	return
}

func (d *driver) RevokeExternalConnectivity(
	request *network.RevokeExternalConnectivityRequest,
) (err error) {
	log.Println("RevokeExternalConnectivity")
	//err = &driverapi.ErrNotImplemented{}
	return
}
