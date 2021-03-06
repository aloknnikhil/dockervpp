// Code generated by GoVPP's binapi-generator. DO NOT EDIT.
// source: /usr/share/vpp/api/core/p2p_ethernet.api.json

/*
Package p2p_ethernet is a generated VPP binary API for 'p2p_ethernet' module.

It consists of:
	  4 messages
	  2 services
*/
package p2p_ethernet

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
	ModuleName = "p2p_ethernet"
	// APIVersion is the API version of this module.
	APIVersion = "1.0.0"
	// VersionCrc is the CRC of this module.
	VersionCrc = 0x65c834be
)

// P2pEthernetAdd represents VPP binary API message 'p2p_ethernet_add'.
type P2pEthernetAdd struct {
	ParentIfIndex uint32
	SubifID       uint32
	RemoteMac     []byte `struc:"[6]byte"`
}

func (*P2pEthernetAdd) GetMessageName() string {
	return "p2p_ethernet_add"
}
func (*P2pEthernetAdd) GetCrcString() string {
	return "7f4abf1a"
}
func (*P2pEthernetAdd) GetMessageType() api.MessageType {
	return api.RequestMessage
}

// P2pEthernetAddReply represents VPP binary API message 'p2p_ethernet_add_reply'.
type P2pEthernetAddReply struct {
	Retval    int32
	SwIfIndex uint32
}

func (*P2pEthernetAddReply) GetMessageName() string {
	return "p2p_ethernet_add_reply"
}
func (*P2pEthernetAddReply) GetCrcString() string {
	return "fda5941f"
}
func (*P2pEthernetAddReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}

// P2pEthernetDel represents VPP binary API message 'p2p_ethernet_del'.
type P2pEthernetDel struct {
	ParentIfIndex uint32
	RemoteMac     []byte `struc:"[6]byte"`
}

func (*P2pEthernetDel) GetMessageName() string {
	return "p2p_ethernet_del"
}
func (*P2pEthernetDel) GetCrcString() string {
	return "1efa374a"
}
func (*P2pEthernetDel) GetMessageType() api.MessageType {
	return api.RequestMessage
}

// P2pEthernetDelReply represents VPP binary API message 'p2p_ethernet_del_reply'.
type P2pEthernetDelReply struct {
	Retval int32
}

func (*P2pEthernetDelReply) GetMessageName() string {
	return "p2p_ethernet_del_reply"
}
func (*P2pEthernetDelReply) GetCrcString() string {
	return "e8d4e804"
}
func (*P2pEthernetDelReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}

func init() {
	api.RegisterMessage((*P2pEthernetAdd)(nil), "p2p_ethernet.P2pEthernetAdd")
	api.RegisterMessage((*P2pEthernetAddReply)(nil), "p2p_ethernet.P2pEthernetAddReply")
	api.RegisterMessage((*P2pEthernetDel)(nil), "p2p_ethernet.P2pEthernetDel")
	api.RegisterMessage((*P2pEthernetDelReply)(nil), "p2p_ethernet.P2pEthernetDelReply")
}

// Messages returns list of all messages in this module.
func AllMessages() []api.Message {
	return []api.Message{
		(*P2pEthernetAdd)(nil),
		(*P2pEthernetAddReply)(nil),
		(*P2pEthernetDel)(nil),
		(*P2pEthernetDelReply)(nil),
	}
}

// RPCService represents RPC service API for p2p_ethernet module.
type RPCService interface {
	P2pEthernetAdd(ctx context.Context, in *P2pEthernetAdd) (*P2pEthernetAddReply, error)
	P2pEthernetDel(ctx context.Context, in *P2pEthernetDel) (*P2pEthernetDelReply, error)
}

type serviceClient struct {
	ch api.Channel
}

func NewServiceClient(ch api.Channel) RPCService {
	return &serviceClient{ch}
}

func (c *serviceClient) P2pEthernetAdd(ctx context.Context, in *P2pEthernetAdd) (*P2pEthernetAddReply, error) {
	out := new(P2pEthernetAddReply)
	err := c.ch.SendRequest(in).ReceiveReply(out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serviceClient) P2pEthernetDel(ctx context.Context, in *P2pEthernetDel) (*P2pEthernetDelReply, error) {
	out := new(P2pEthernetDelReply)
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
