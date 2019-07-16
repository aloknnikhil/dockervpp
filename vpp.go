package dockervpp

import (
	"dockervpp/bin_api/interfaces"
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
	gateway  interfaces.InterfaceIndex
	segments []interfaces.InterfaceIndex
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

	request := &interfaces.CreateLoopback{
		MacAddress: mac,
	}

	// Dispatch request
	response := b.Channel.SendRequest(request)
	reply := &interfaces.CreateLoopbackReply{}
	if err = response.ReceiveReply(reply); err != nil {
		err = errors.Wrap(err, "response.ReceiveReply()")
		return
	}
	if reply.Retval != 0 {
		err = errors.Errorf("CreateLoopbackReply: %d error", reply.Retval)
		return
	}
	b.gateway = interfaces.InterfaceIndex(reply.SwIfIndex)

	return
}

func (b *bridge) DeleteGateway() (err error) {

}

func (b *bridge) AddSegment(intidx interfaces.InterfaceIndex) (err error) {
	if b.Channel == nil {
		err = errors.New("No VPP client session")
		return
	}

	return
}
