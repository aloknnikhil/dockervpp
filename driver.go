package dockervpp

import (
	"log"
	"net"
	"os/user"
	"reflect"
	"strconv"
	"sync"
	"syscall"

	"github.com/nikhil93uf/dockervpp/bin_api/l2"

	"git.fd.io/govpp.git/core"

	"git.fd.io/govpp.git/api"
	"github.com/vishvananda/netns"

	"github.com/FDio/govpp"

	"github.com/docker/libnetwork/types"

	"github.com/docker/docker/pkg/plugins"
	pluginapi "github.com/docker/go-plugins-helpers/network"
	"github.com/docker/libnetwork/netlabel"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
)

// Configuration for the VPP API socket path
const (
	VPPAPISock string = "/var/run/vpp/vpp-api.sock"
)

// Client to interact with VPP
var Client driver

// General NAT API helper
var natclient *vppnat

// Monotonic Bridge ID counter
// Skips the default bridge domain
var bridgeID uint32 = 1

// TODO: Consolidate device & vppinterface structs
type device struct {
	// Maps to the other end of the device in VPP
	peer *vppinterface
	netlink.Link
	address   net.IP
	state     netlink.LinkOperState
	id        string
	networkID string
}

type network struct {
	// Maps to a bridge configuration in VPP
	*vppbridge
	id        string
	options   map[string]interface{}
	endpoints []*device
}

type driver struct {
	// Synchronization primitives
	sync.Once
	sync.WaitGroup

	// VPP client connection
	// TODO: Wrap client in a retryable client for repairs
	vppcnx *core.Connection
	vppapi api.Channel

	// Docker API client
	docker *plugins.Client

	// Linux Netlink client
	nlink *netlink.Handle

	// Cache
	// Network ID -> dockervpp.network
	networks map[string]*network
	// Endpoint ID -> dockervpp.device
	endpoints map[string]*device
	// Endpoint ID -> Port Mapping (NAT) rules
	natrules map[string][]portmapping
}

func (d *driver) Close() (err error) {
	// Log errors, if any
	defer func() {
		if err != nil {
			log.Printf("[Error] %s\n", err.Error())
		}
	}()

	d.vppcnx.Disconnect()

	// TODO: Clean shutdown docker plugin server
	return
}

func (d *driver) Run(username string) (err error) {
	// Log errors, if any
	defer func() {
		if err != nil {
			log.Printf("[Error] %s\n", err.Error())
		}
	}()

	d.Do(func() {

		d.networks = make(map[string]*network)
		d.endpoints = make(map[string]*device)
		d.natrules = make(map[string][]portmapping)

		// Connect to VPP
		if d.vppcnx, err = govpp.Connect(VPPAPISock); err != nil {
			err = errors.Wrap(err, "govpp.Connect()")
			return
		}
		if d.vppapi, err = d.vppcnx.NewAPIChannel(); err != nil {
			err = errors.Wrap(err, "vpp.NewAPIChannel()")
			return
		}
		natclient = &vppnat{
			Channel:       d.vppapi,
			externalports: make(map[port]struct{}),
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

		if err = pluginapi.NewHandler(d).ServeUnix("vpp", gid); err != nil {
			err = errors.Wrap(err, "pluginapi.NewHandler().ServeUnix")
			return
		}
	})

	return
}

func (d *driver) AllocateNetwork(
	request *pluginapi.AllocateNetworkRequest,
) (response *pluginapi.AllocateNetworkResponse, err error) {
	// Log errors, if any
	defer func() {
		if err != nil {
			log.Printf("[Error] %s\n", err.Error())
		}
	}()

	log.Println("AllocateNetwork")
	//err = &driverapi.ErrNotImplemented{}
	return
}

func (d *driver) CreateEndpoint(
	request *pluginapi.CreateEndpointRequest,
) (response *pluginapi.CreateEndpointResponse, err error) {
	// Log errors, if any
	defer func() {
		if err != nil {
			log.Printf("[Error] %s\n", err.Error())
		}
	}()

	log.Println("CreateEndpoint")

	if request.Interface == nil {
		err = errors.Wrap(err, "Invalid interface specified")
		return
	}

	// Check if network is cached (and thus created)
	var network *network
	var ok bool
	if network, ok = d.networks[request.NetworkID]; !ok {
		err = errors.Errorf("Network - %s doesn't exist", request.NetworkID)
		return
	}

	// Create VETH pair for end-point
	vETH := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "VPP" + request.EndpointID[:4]},
		PeerName:  "VETH" + request.EndpointID[:4],
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

	response = &pluginapi.CreateEndpointResponse{}

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
		response.Interface = &pluginapi.EndpointInterface{
			MacAddress: peer.Attrs().HardwareAddr.String(),
		}
	}

	// Set IP address
	var ip4 *netlink.Addr
	var ip6 *netlink.Addr
	if len(request.Interface.Address) != 0 {
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
		if ip6, err = netlink.ParseAddr(request.Interface.AddressIPv6); err != nil {
			err = errors.Wrapf(err, "netlink.ParseAddr(%s)", request.Interface.AddressIPv6)
			return
		}
		if err = d.nlink.AddrAdd(peer, ip6); err != nil {
			err = errors.Wrapf(err, "netlink.AddrAdd(%s)", request.Interface.AddressIPv6)
			return
		}
	}

	// Cache VETH
	device := &device{
		id:        request.EndpointID,
		networkID: request.NetworkID,
		Link:      vETH,
	}

	if ip4 != nil {
		device.address = ip4.IP
	}

	// Initialize the other end of the VETH in VPP
	if device.peer, err = createHostInterface(d.vppapi, vETH); err != nil {
		err = errors.Wrap(err, "createHostInterface()")
		return
	}

	// Add endpoint to network cache
	network.endpoints = append(network.endpoints, device)
	d.endpoints[request.EndpointID] = device
	return
}

func (d *driver) CreateNetwork(
	request *pluginapi.CreateNetworkRequest,
) (err error) {
	// Log errors, if any
	defer func() {
		if err != nil {
			log.Printf("[Error] %s\n", err.Error())
		}
	}()

	log.Println("CreateNetwork")

	// Get Network ID
	if len(request.Options) == 0 {
		err = errors.New("CreateNetwork: No create options specified")
		return
	}

	// Container for caching
	network := &network{
		id:      request.NetworkID,
		options: request.Options,
		vppbridge: &vppbridge{
			Channel: d.vppapi,
			ID:      bridgeID,
		},
	}

	// Parse options
	isIPV6 := false
	var ipv6 net.IP
	var ipv6Subnet *net.IPNet
	for option, value := range request.Options {
		switch option {
		case netlabel.EnableIPv6:
			ok := false
			if isIPV6, ok = value.(bool); !ok {
				err = errors.Errorf("CreateNetwork: Invalid value for %s", netlabel.Prefix+netlabel.EnableIPv6)
				return
			}

			// If IPv6, verify there's atleast 1 subnet specified
			if isIPV6 {
				if len(request.IPv6Data) == 0 {
					err = errors.New("CreateNetwork: IPv6 requested but no subnet specified")
					return
				}
				if ipv6, _, err = net.ParseCIDR(request.IPv6Data[0].Gateway); err != nil {
					err = errors.Errorf("CreateNetwork: Could not parse IPv6 Gateway: %s", err.Error())
					return
				}
				if _, ipv6Subnet, err = net.ParseCIDR(request.IPv6Data[0].Pool); err != nil {
					err = errors.Errorf("CreateNetwork: Could not parse IPv6 Pool: %s", err.Error())
					return
				}
			}
		}
	}

	// If IPv4, verify there's atleast 1 subnet specified
	var ipv4 net.IP
	var ipv4Subnet *net.IPNet
	if len(request.IPv4Data) == 0 {
		if !isIPV6 {
			err = errors.New("No IPv4/6 subnets specified")
			return
		}
	} else {
		if ipv4, _, err = net.ParseCIDR(request.IPv4Data[0].Gateway); err != nil {
			err = errors.Errorf("CreateNetwork: Could not parse IPv4 Gateway: %s", err.Error())
			return
		}
		if _, ipv4Subnet, err = net.ParseCIDR(request.IPv4Data[0].Pool); err != nil {
			err = errors.Errorf("CreateNetwork: Could not parse IPv4 Pool: %s", err.Error())
			return
		}
	}

	// If not internal, create gateway
	var value interface{}
	var internal bool
	var ok bool
	if value, ok = request.Options[netlabel.Internal]; ok {
		internal = value.(bool)
	}

	// Create VPP bridge
	if !internal {
		if err = network.vppbridge.CreateGateway(ipv4, ipv4Subnet, ipv6, ipv6Subnet, nil); err != nil {
			err = errors.Wrap(err, "vppbridge.CreateGateway()")
			return
		}
		bridgeID++

		// Set gateway as inside NAT
		if err = natclient.Enable(network.gateway, in); err != nil {
			err = errors.Wrap(err, "natclient.Enable()")
			return
		}
	}
	// Cache network
	d.networks[request.NetworkID] = network
	return
}

func (d *driver) DeleteEndpoint(
	request *pluginapi.DeleteEndpointRequest,
) (err error) {
	// Log errors, if any
	defer func() {
		if err != nil {
			log.Printf("[Error] %s\n", err.Error())
		}
	}()

	log.Println("DeleteEndpoint")

	// Check if the endpoint exists
	var endpoint *device
	var ok bool
	if endpoint, ok = d.endpoints[request.EndpointID]; !ok {
		err = errors.Errorf("Endpoint - %s doesn't exist", request.EndpointID)
		return
	}

	// Cleanup based on the link type
	switch link := endpoint.Link.(type) {
	case *netlink.Veth:
		var peer netlink.Link
		if peer, err = d.nlink.LinkByName(link.PeerName); err != nil {
			err = errors.Wrap(err, "netlink.LinkByName()")
			return
		}

		if err = d.nlink.LinkDel(peer); err != nil {
			err = errors.Wrapf(err, "netlink.LinkDel(%+v)", peer)
			return
		}

		// Delete VPP end of the link
		if err = endpoint.peer.Delete(); err != nil {
			err = errors.Wrap(err, "endpoint.vppinterface.Delete()")
			return
		}
	default:
		err = errors.Errorf("Endpoint - %s unknown type", request.EndpointID)
		return
	}

	// Delete from cache
	delete(d.endpoints, request.EndpointID)

	// Set link state to reflect state in other caches
	endpoint.state = netlink.OperNotPresent
	return
}

func (d *driver) DeleteNetwork(
	request *pluginapi.DeleteNetworkRequest,
) (err error) {
	// Log errors, if any
	defer func() {
		if err != nil {
			log.Printf("[Error] %s\n", err.Error())
		}
	}()

	log.Println("DeleteNetwork")

	// Check if the network exists
	var network *network
	var ok bool
	if network, ok = d.networks[request.NetworkID]; !ok {
		err = errors.Errorf("Network - %s doesn't exist", request.NetworkID)
		return
	}

	// Delete each endpoint, if any
	for _, endpoint := range network.endpoints {
		if endpoint.state != netlink.OperNotPresent {
			deletereq := &pluginapi.DeleteEndpointRequest{
				NetworkID:  request.NetworkID,
				EndpointID: endpoint.id,
			}
			if err = d.DeleteEndpoint(deletereq); err != nil {
				err = errors.Wrap(err, "d.DeleteEndpoint()")
				return
			}
		}
	}

	// Delete the network bridge
	if network.vppbridge != nil {
		if err = network.vppbridge.Close(); err != nil {
			err = errors.Wrap(err, "network.vppbridge.Close()")
			return
		}
		network.vppbridge = nil
	}

	// Delete from cache
	delete(d.networks, request.NetworkID)

	return
}

func (d *driver) DiscoverDelete(
	notification *pluginapi.DiscoveryNotification,
) (err error) {
	// Log errors, if any
	defer func() {
		if err != nil {
			log.Printf("[Error] %s\n", err.Error())
		}
	}()

	log.Println("DiscoverDelete")
	//err = &driverapi.ErrNotImplemented{}
	return
}

func (d *driver) DiscoverNew(
	notification *pluginapi.DiscoveryNotification,
) (err error) {
	// Log errors, if any
	defer func() {
		if err != nil {
			log.Printf("[Error] %s\n", err.Error())
		}
	}()

	log.Println("DiscoverNew")
	//err = &driverapi.ErrNotImplemented{}
	return
}

func (d *driver) EndpointInfo(
	request *pluginapi.InfoRequest,
) (response *pluginapi.InfoResponse, err error) {
	// Log errors, if any
	defer func() {
		if err != nil {
			log.Printf("[Error] %s\n", err.Error())
		}
	}()

	log.Println("EndpointInfo")

	// Get endpoint
	var endpoint *device
	var ok bool
	if endpoint, ok = d.endpoints[request.EndpointID]; !ok {
		err = errors.Errorf("Endpoint - %s doesn't exist", request.EndpointID)
		return
	}

	response = &pluginapi.InfoResponse{
		Value: make(map[string]string),
	}

	// Send a copy of the current endpoint configuration
	response.Value[netlabel.MacAddress] = endpoint.Attrs().HardwareAddr.String()

	return
}

func (d *driver) FreeNetwork(
	request *pluginapi.FreeNetworkRequest,
) (err error) {
	// Log errors, if any
	defer func() {
		if err != nil {
			log.Printf("[Error] %s\n", err.Error())
		}
	}()

	log.Println("FreeNetwork")
	//err = &driverapi.ErrNotImplemented{}
	return
}

func (d *driver) GetCapabilities() (
	response *pluginapi.CapabilitiesResponse, err error,
) {
	// Log errors, if any
	defer func() {
		if err != nil {
			log.Printf("[Error] %s\n", err.Error())
		}
	}()

	log.Println("GetCapabilities")
	response = &pluginapi.CapabilitiesResponse{Scope: pluginapi.LocalScope, ConnectivityScope: pluginapi.GlobalScope}
	return
}

func (d *driver) Join(
	request *pluginapi.JoinRequest,
) (response *pluginapi.JoinResponse, err error) {
	// Log errors, if any
	defer func() {
		if err != nil {
			log.Printf("[Error] %s\n", err.Error())
		}
	}()

	log.Println("Join")

	var network *network
	var ok bool
	if network, ok = d.networks[request.NetworkID]; !ok {
		err = errors.Errorf("Network - %s doesn't exist", request.NetworkID)
		return
	}

	var intfc *device
	if intfc, ok = d.endpoints[request.EndpointID]; !ok {
		err = errors.Errorf("Endpoint - %s doesn't exist", request.EndpointID)
		return
	}

	if err = network.vppbridge.AddInterface(intfc.peer, l2.L2_API_PORT_TYPE_NORMAL); err != nil {
		err = errors.Wrap(err, "network.vppbridge.AddInterface()")
		return
	}
	if err = intfc.peer.Up(); err != nil {
		err = errors.Wrap(err, "vhost.Up()")
		return
	}

	response = &pluginapi.JoinResponse{
		InterfaceName: pluginapi.InterfaceName{
			DstPrefix: "narf",
		},
		DisableGatewayService: true,
	}

	if network.gateway != nil {
		if network.gateway.ipV4 != nil {
			response.Gateway = network.gateway.ipV4.String()
			response.DisableGatewayService = false
		}

		if network.gateway.ipV6 != nil {
			response.Gateway = network.gateway.ipV6.String()
			response.DisableGatewayService = false
		}
	}

	switch link := intfc.Link.(type) {
	case *netlink.Veth:
		response.InterfaceName.SrcName = link.PeerName
	default:
		response = nil
		err = errors.Errorf("Endpoint - %s unknown type", request.EndpointID)
		return
	}
	return
}

func (d *driver) Leave(
	request *pluginapi.LeaveRequest,
) (err error) {
	// Log errors, if any
	defer func() {
		if err != nil {
			log.Printf("[Error] %s\n", err.Error())
		}
	}()

	log.Println("Leave")
	// DeleteEndpoint also deletes the VPP end of the interface. Nothing to do here
	return
}

func (d *driver) ProgramExternalConnectivity(
	request *pluginapi.ProgramExternalConnectivityRequest,
) (err error) {
	// Log errors, if any
	defer func() {
		if err != nil {
			log.Printf("[Error] %s\n", err.Error())
		}
	}()

	log.Println("ProgramExternalConnectivity")

	// Get endpoint
	var endpoint *device
	var ok bool
	if endpoint, ok = d.endpoints[request.EndpointID]; !ok {
		err = errors.Errorf("Endpoint - %s doesn't exist", request.EndpointID)
		return
	}

	// Parse connectivity options
	for key, value := range request.Options {
		log.Printf("key - %s; check - %s", key, netlabel.Prefix+netlabel.PortMap)
		switch key {
		case netlabel.PortMap:
			var mapping []interface{}
			var ok bool
			if mapping, ok = value.([]interface{}); !ok {
				err = types.BadRequestErrorf("Invalid port mapping data in configuration: %+v - Type: %s", value, reflect.TypeOf(value))
				return
			}
			var rules []portmapping
			for _, element := range mapping {

				var portmap map[string]interface{}
				if portmap, ok = element.(map[string]interface{}); !ok {
					err = types.BadRequestErrorf("Invalid port mapping data in configuration: %+v - Type: %s", element, reflect.TypeOf(element))
					return
				}

				// Read host port
				if value, ok = portmap["HostPort"]; !ok {
					err = errors.New("No host port specified in port mapping configuration")
					return
				}
				var externalport float64
				if externalport, ok = value.(float64); !ok {
					err = errors.Errorf("Invalid HostPort value - %+v", value)
					return
				}

				// Read internal port
				if value, ok = portmap["Port"]; !ok {
					err = errors.New("No local port specified in port mapping configuration")
					return
				}
				var internalport float64
				if internalport, ok = value.(float64); !ok {
					err = errors.Errorf("Invalid Port value - %+v", value)
					return
				}

				// Read protocol type
				if value, ok = portmap["Proto"]; !ok {
					err = errors.New("No protocol type specified in port mapping configuration")
					return
				}
				var proto float64
				if proto, ok = value.(float64); !ok {
					err = errors.Errorf("Invalid Protocol value - %+v", value)
					return
				}

				rule := portmapping{
					internalip:   endpoint.address,
					internalport: port(internalport),
					externalport: port(externalport),
					protocol:     uint8(proto),
				}
				rules = append(rules, rule)
			}

			// Program VPP
			if err = natclient.MapPorts(rules); err != nil {
				err = errors.Wrapf(err, "nat.MapPorts(%+v)", rules)
				return
			}

			// Cache
			d.natrules[request.EndpointID] = append(d.natrules[request.EndpointID], rules...)
		default:
			log.Printf("[WARN] Unknown configuration key - %s; Ignoring", key)
		}
	}

	return
}

func (d *driver) RevokeExternalConnectivity(
	request *pluginapi.RevokeExternalConnectivityRequest,
) (err error) {
	// Log errors, if any
	defer func() {
		if err != nil {
			log.Printf("[Error] %s\n", err.Error())
		}
	}()

	log.Println("RevokeExternalConnectivity")

	// Remove all port maps
	var rules []portmapping
	var ok bool
	if rules, ok = d.natrules[request.EndpointID]; !ok {
		// No maps; nothing to do
		return
	}

	if err = natclient.UnmapPorts(rules); err != nil {
		err = errors.Wrap(err, "natclient.UnmapPorts()")
		return
	}

	return
}
