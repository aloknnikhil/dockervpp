// Code generated by GoVPP's binapi-generator. DO NOT EDIT.
// source: /usr/share/vpp/api/core/ipip.api.json

/*
Package ipip is a generated VPP binary API for 'ipip' module.

It consists of:
	  1 alias
	 10 messages
	  5 services
*/
package ipip

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
	ModuleName = "ipip"
	// APIVersion is the API version of this module.
	APIVersion = "1.1.0"
	// VersionCrc is the CRC of this module.
	VersionCrc = 0xc6f9c052
)

// InterfaceIndex represents VPP binary API alias 'interface_index'.
type InterfaceIndex uint32

// Ipip6rdAddTunnel represents VPP binary API message 'ipip_6rd_add_tunnel'.
type Ipip6rdAddTunnel struct {
	IP6TableID    uint32
	IP4TableID    uint32
	IP6Prefix     []byte `struc:"[16]byte"`
	IP4Prefix     []byte `struc:"[4]byte"`
	IP4Src        []byte `struc:"[4]byte"`
	IP6PrefixLen  uint8
	IP4PrefixLen  uint8
	SecurityCheck uint8
	TcTos         uint8
}

func (*Ipip6rdAddTunnel) GetMessageName() string {
	return "ipip_6rd_add_tunnel"
}
func (*Ipip6rdAddTunnel) GetCrcString() string {
	return "c5005266"
}
func (*Ipip6rdAddTunnel) GetMessageType() api.MessageType {
	return api.RequestMessage
}

// Ipip6rdAddTunnelReply represents VPP binary API message 'ipip_6rd_add_tunnel_reply'.
type Ipip6rdAddTunnelReply struct {
	Retval    int32
	SwIfIndex InterfaceIndex
}

func (*Ipip6rdAddTunnelReply) GetMessageName() string {
	return "ipip_6rd_add_tunnel_reply"
}
func (*Ipip6rdAddTunnelReply) GetCrcString() string {
	return "903324db"
}
func (*Ipip6rdAddTunnelReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}

// Ipip6rdDelTunnel represents VPP binary API message 'ipip_6rd_del_tunnel'.
type Ipip6rdDelTunnel struct {
	SwIfIndex InterfaceIndex
}

func (*Ipip6rdDelTunnel) GetMessageName() string {
	return "ipip_6rd_del_tunnel"
}
func (*Ipip6rdDelTunnel) GetCrcString() string {
	return "d85aab0d"
}
func (*Ipip6rdDelTunnel) GetMessageType() api.MessageType {
	return api.RequestMessage
}

// Ipip6rdDelTunnelReply represents VPP binary API message 'ipip_6rd_del_tunnel_reply'.
type Ipip6rdDelTunnelReply struct {
	Retval int32
}

func (*Ipip6rdDelTunnelReply) GetMessageName() string {
	return "ipip_6rd_del_tunnel_reply"
}
func (*Ipip6rdDelTunnelReply) GetCrcString() string {
	return "e8d4e804"
}
func (*Ipip6rdDelTunnelReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}

// IpipAddTunnel represents VPP binary API message 'ipip_add_tunnel'.
type IpipAddTunnel struct {
	IsIPv6     uint8
	Instance   uint32
	SrcAddress []byte `struc:"[16]byte"`
	DstAddress []byte `struc:"[16]byte"`
	TableID    uint32
	TcTos      uint8
}

func (*IpipAddTunnel) GetMessageName() string {
	return "ipip_add_tunnel"
}
func (*IpipAddTunnel) GetCrcString() string {
	return "5c80fd36"
}
func (*IpipAddTunnel) GetMessageType() api.MessageType {
	return api.RequestMessage
}

// IpipAddTunnelReply represents VPP binary API message 'ipip_add_tunnel_reply'.
type IpipAddTunnelReply struct {
	Retval    int32
	SwIfIndex InterfaceIndex
}

func (*IpipAddTunnelReply) GetMessageName() string {
	return "ipip_add_tunnel_reply"
}
func (*IpipAddTunnelReply) GetCrcString() string {
	return "903324db"
}
func (*IpipAddTunnelReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}

// IpipDelTunnel represents VPP binary API message 'ipip_del_tunnel'.
type IpipDelTunnel struct {
	SwIfIndex InterfaceIndex
}

func (*IpipDelTunnel) GetMessageName() string {
	return "ipip_del_tunnel"
}
func (*IpipDelTunnel) GetCrcString() string {
	return "d85aab0d"
}
func (*IpipDelTunnel) GetMessageType() api.MessageType {
	return api.RequestMessage
}

// IpipDelTunnelReply represents VPP binary API message 'ipip_del_tunnel_reply'.
type IpipDelTunnelReply struct {
	Retval int32
}

func (*IpipDelTunnelReply) GetMessageName() string {
	return "ipip_del_tunnel_reply"
}
func (*IpipDelTunnelReply) GetCrcString() string {
	return "e8d4e804"
}
func (*IpipDelTunnelReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}

// IpipTunnelDetails represents VPP binary API message 'ipip_tunnel_details'.
type IpipTunnelDetails struct {
	SwIfIndex  InterfaceIndex
	Instance   uint32
	IsIPv6     uint8
	SrcAddress []byte `struc:"[16]byte"`
	DstAddress []byte `struc:"[16]byte"`
	FibIndex   uint32
	TcTos      uint8
}

func (*IpipTunnelDetails) GetMessageName() string {
	return "ipip_tunnel_details"
}
func (*IpipTunnelDetails) GetCrcString() string {
	return "20202342"
}
func (*IpipTunnelDetails) GetMessageType() api.MessageType {
	return api.ReplyMessage
}

// IpipTunnelDump represents VPP binary API message 'ipip_tunnel_dump'.
type IpipTunnelDump struct {
	SwIfIndex InterfaceIndex
}

func (*IpipTunnelDump) GetMessageName() string {
	return "ipip_tunnel_dump"
}
func (*IpipTunnelDump) GetCrcString() string {
	return "d85aab0d"
}
func (*IpipTunnelDump) GetMessageType() api.MessageType {
	return api.RequestMessage
}

func init() {
	api.RegisterMessage((*Ipip6rdAddTunnel)(nil), "ipip.Ipip6rdAddTunnel")
	api.RegisterMessage((*Ipip6rdAddTunnelReply)(nil), "ipip.Ipip6rdAddTunnelReply")
	api.RegisterMessage((*Ipip6rdDelTunnel)(nil), "ipip.Ipip6rdDelTunnel")
	api.RegisterMessage((*Ipip6rdDelTunnelReply)(nil), "ipip.Ipip6rdDelTunnelReply")
	api.RegisterMessage((*IpipAddTunnel)(nil), "ipip.IpipAddTunnel")
	api.RegisterMessage((*IpipAddTunnelReply)(nil), "ipip.IpipAddTunnelReply")
	api.RegisterMessage((*IpipDelTunnel)(nil), "ipip.IpipDelTunnel")
	api.RegisterMessage((*IpipDelTunnelReply)(nil), "ipip.IpipDelTunnelReply")
	api.RegisterMessage((*IpipTunnelDetails)(nil), "ipip.IpipTunnelDetails")
	api.RegisterMessage((*IpipTunnelDump)(nil), "ipip.IpipTunnelDump")
}

// Messages returns list of all messages in this module.
func AllMessages() []api.Message {
	return []api.Message{
		(*Ipip6rdAddTunnel)(nil),
		(*Ipip6rdAddTunnelReply)(nil),
		(*Ipip6rdDelTunnel)(nil),
		(*Ipip6rdDelTunnelReply)(nil),
		(*IpipAddTunnel)(nil),
		(*IpipAddTunnelReply)(nil),
		(*IpipDelTunnel)(nil),
		(*IpipDelTunnelReply)(nil),
		(*IpipTunnelDetails)(nil),
		(*IpipTunnelDump)(nil),
	}
}

// RPCService represents RPC service API for ipip module.
type RPCService interface {
	DumpIpipTunnel(ctx context.Context, in *IpipTunnelDump) (RPCService_DumpIpipTunnelClient, error)
	Ipip6rdAddTunnel(ctx context.Context, in *Ipip6rdAddTunnel) (*Ipip6rdAddTunnelReply, error)
	Ipip6rdDelTunnel(ctx context.Context, in *Ipip6rdDelTunnel) (*Ipip6rdDelTunnelReply, error)
	IpipAddTunnel(ctx context.Context, in *IpipAddTunnel) (*IpipAddTunnelReply, error)
	IpipDelTunnel(ctx context.Context, in *IpipDelTunnel) (*IpipDelTunnelReply, error)
}

type serviceClient struct {
	ch api.Channel
}

func NewServiceClient(ch api.Channel) RPCService {
	return &serviceClient{ch}
}

func (c *serviceClient) DumpIpipTunnel(ctx context.Context, in *IpipTunnelDump) (RPCService_DumpIpipTunnelClient, error) {
	stream := c.ch.SendMultiRequest(in)
	x := &serviceClient_DumpIpipTunnelClient{stream}
	return x, nil
}

type RPCService_DumpIpipTunnelClient interface {
	Recv() (*IpipTunnelDetails, error)
}

type serviceClient_DumpIpipTunnelClient struct {
	api.MultiRequestCtx
}

func (c *serviceClient_DumpIpipTunnelClient) Recv() (*IpipTunnelDetails, error) {
	m := new(IpipTunnelDetails)
	stop, err := c.MultiRequestCtx.ReceiveReply(m)
	if err != nil {
		return nil, err
	}
	if stop {
		return nil, io.EOF
	}
	return m, nil
}

func (c *serviceClient) Ipip6rdAddTunnel(ctx context.Context, in *Ipip6rdAddTunnel) (*Ipip6rdAddTunnelReply, error) {
	out := new(Ipip6rdAddTunnelReply)
	err := c.ch.SendRequest(in).ReceiveReply(out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serviceClient) Ipip6rdDelTunnel(ctx context.Context, in *Ipip6rdDelTunnel) (*Ipip6rdDelTunnelReply, error) {
	out := new(Ipip6rdDelTunnelReply)
	err := c.ch.SendRequest(in).ReceiveReply(out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serviceClient) IpipAddTunnel(ctx context.Context, in *IpipAddTunnel) (*IpipAddTunnelReply, error) {
	out := new(IpipAddTunnelReply)
	err := c.ch.SendRequest(in).ReceiveReply(out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serviceClient) IpipDelTunnel(ctx context.Context, in *IpipDelTunnel) (*IpipDelTunnelReply, error) {
	out := new(IpipDelTunnelReply)
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