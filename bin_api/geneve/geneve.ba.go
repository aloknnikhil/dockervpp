// Code generated by GoVPP's binapi-generator. DO NOT EDIT.
// source: /usr/share/vpp/api/core/geneve.api.json

/*
Package geneve is a generated VPP binary API for 'geneve' module.

It consists of:
	  6 messages
	  3 services
*/
package geneve

import (
	bytes "bytes"
	context "context"
	api "git.fd.io/govpp.git/api"
	struc "github.com/lunixbochs/struc"
	io "io"
	strconv "strconv"
)

const (
	// ModuleName is the name of this module.
	ModuleName = "geneve"
	// APIVersion is the API version of this module.
	APIVersion = "1.0.0"
	// VersionCrc is the CRC of this module.
	VersionCrc = 0xe0ad9743
)

// GeneveAddDelTunnel represents VPP binary API message 'geneve_add_del_tunnel'.
type GeneveAddDelTunnel struct {
	IsAdd          uint8
	IsIPv6         uint8
	LocalAddress   []byte `struc:"[16]byte"`
	RemoteAddress  []byte `struc:"[16]byte"`
	McastSwIfIndex uint32
	EncapVrfID     uint32
	DecapNextIndex uint32
	Vni            uint32
}

func (*GeneveAddDelTunnel) GetMessageName() string {
	return "geneve_add_del_tunnel"
}
func (*GeneveAddDelTunnel) GetCrcString() string {
	return "403cf981"
}
func (*GeneveAddDelTunnel) GetMessageType() api.MessageType {
	return api.RequestMessage
}

// GeneveAddDelTunnelReply represents VPP binary API message 'geneve_add_del_tunnel_reply'.
type GeneveAddDelTunnelReply struct {
	Retval    int32
	SwIfIndex uint32
}

func (*GeneveAddDelTunnelReply) GetMessageName() string {
	return "geneve_add_del_tunnel_reply"
}
func (*GeneveAddDelTunnelReply) GetCrcString() string {
	return "fda5941f"
}
func (*GeneveAddDelTunnelReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}

// GeneveTunnelDetails represents VPP binary API message 'geneve_tunnel_details'.
type GeneveTunnelDetails struct {
	SwIfIndex      uint32
	SrcAddress     []byte `struc:"[16]byte"`
	DstAddress     []byte `struc:"[16]byte"`
	McastSwIfIndex uint32
	EncapVrfID     uint32
	DecapNextIndex uint32
	Vni            uint32
	IsIPv6         uint8
}

func (*GeneveTunnelDetails) GetMessageName() string {
	return "geneve_tunnel_details"
}
func (*GeneveTunnelDetails) GetCrcString() string {
	return "024fa31f"
}
func (*GeneveTunnelDetails) GetMessageType() api.MessageType {
	return api.ReplyMessage
}

// GeneveTunnelDump represents VPP binary API message 'geneve_tunnel_dump'.
type GeneveTunnelDump struct {
	SwIfIndex uint32
}

func (*GeneveTunnelDump) GetMessageName() string {
	return "geneve_tunnel_dump"
}
func (*GeneveTunnelDump) GetCrcString() string {
	return "529cb13f"
}
func (*GeneveTunnelDump) GetMessageType() api.MessageType {
	return api.RequestMessage
}

// SwInterfaceSetGeneveBypass represents VPP binary API message 'sw_interface_set_geneve_bypass'.
type SwInterfaceSetGeneveBypass struct {
	SwIfIndex uint32
	IsIPv6    uint8
	Enable    uint8
}

func (*SwInterfaceSetGeneveBypass) GetMessageName() string {
	return "sw_interface_set_geneve_bypass"
}
func (*SwInterfaceSetGeneveBypass) GetCrcString() string {
	return "e74ca095"
}
func (*SwInterfaceSetGeneveBypass) GetMessageType() api.MessageType {
	return api.RequestMessage
}

// SwInterfaceSetGeneveBypassReply represents VPP binary API message 'sw_interface_set_geneve_bypass_reply'.
type SwInterfaceSetGeneveBypassReply struct {
	Retval int32
}

func (*SwInterfaceSetGeneveBypassReply) GetMessageName() string {
	return "sw_interface_set_geneve_bypass_reply"
}
func (*SwInterfaceSetGeneveBypassReply) GetCrcString() string {
	return "e8d4e804"
}
func (*SwInterfaceSetGeneveBypassReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}

func init() {
	api.RegisterMessage((*GeneveAddDelTunnel)(nil), "geneve.GeneveAddDelTunnel")
	api.RegisterMessage((*GeneveAddDelTunnelReply)(nil), "geneve.GeneveAddDelTunnelReply")
	api.RegisterMessage((*GeneveTunnelDetails)(nil), "geneve.GeneveTunnelDetails")
	api.RegisterMessage((*GeneveTunnelDump)(nil), "geneve.GeneveTunnelDump")
	api.RegisterMessage((*SwInterfaceSetGeneveBypass)(nil), "geneve.SwInterfaceSetGeneveBypass")
	api.RegisterMessage((*SwInterfaceSetGeneveBypassReply)(nil), "geneve.SwInterfaceSetGeneveBypassReply")
}

// Messages returns list of all messages in this module.
func AllMessages() []api.Message {
	return []api.Message{
		(*GeneveAddDelTunnel)(nil),
		(*GeneveAddDelTunnelReply)(nil),
		(*GeneveTunnelDetails)(nil),
		(*GeneveTunnelDump)(nil),
		(*SwInterfaceSetGeneveBypass)(nil),
		(*SwInterfaceSetGeneveBypassReply)(nil),
	}
}

// RPCService represents RPC service API for geneve module.
type RPCService interface {
	DumpGeneveTunnel(ctx context.Context, in *GeneveTunnelDump) (RPCService_DumpGeneveTunnelClient, error)
	GeneveAddDelTunnel(ctx context.Context, in *GeneveAddDelTunnel) (*GeneveAddDelTunnelReply, error)
	SwInterfaceSetGeneveBypass(ctx context.Context, in *SwInterfaceSetGeneveBypass) (*SwInterfaceSetGeneveBypassReply, error)
}

type serviceClient struct {
	ch api.Channel
}

func NewServiceClient(ch api.Channel) RPCService {
	return &serviceClient{ch}
}

func (c *serviceClient) DumpGeneveTunnel(ctx context.Context, in *GeneveTunnelDump) (RPCService_DumpGeneveTunnelClient, error) {
	stream := c.ch.SendMultiRequest(in)
	x := &serviceClient_DumpGeneveTunnelClient{stream}
	return x, nil
}

type RPCService_DumpGeneveTunnelClient interface {
	Recv() (*GeneveTunnelDetails, error)
}

type serviceClient_DumpGeneveTunnelClient struct {
	api.MultiRequestCtx
}

func (c *serviceClient_DumpGeneveTunnelClient) Recv() (*GeneveTunnelDetails, error) {
	m := new(GeneveTunnelDetails)
	stop, err := c.MultiRequestCtx.ReceiveReply(m)
	if err != nil {
		return nil, err
	}
	if stop {
		return nil, io.EOF
	}
	return m, nil
}

func (c *serviceClient) GeneveAddDelTunnel(ctx context.Context, in *GeneveAddDelTunnel) (*GeneveAddDelTunnelReply, error) {
	out := new(GeneveAddDelTunnelReply)
	err := c.ch.SendRequest(in).ReceiveReply(out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serviceClient) SwInterfaceSetGeneveBypass(ctx context.Context, in *SwInterfaceSetGeneveBypass) (*SwInterfaceSetGeneveBypassReply, error) {
	out := new(SwInterfaceSetGeneveBypassReply)
	err := c.ch.SendRequest(in).ReceiveReply(out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// This is a compile-time assertion to ensure that this generated file
// is compatible with the GoVPP api package it is being compiled against.
// A compilation error at this line likely means your copy of the
// GoVPP api package needs to be updated.
const _ = api.GoVppAPIPackageIsVersion1 // please upgrade the GoVPP api package

// Reference imports to suppress errors if they are not otherwise used.
var _ = api.RegisterMessage
var _ = bytes.NewBuffer
var _ = context.Background
var _ = io.Copy
var _ = strconv.Itoa
var _ = struc.Pack
