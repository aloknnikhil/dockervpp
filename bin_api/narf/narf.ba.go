// Code generated by GoVPP's binapi-generator. DO NOT EDIT.
// source: /usr/share/vpp/api/plugins/narf.api.json

/*
Package narf is a generated VPP binary API for 'narf' module.

It consists of:
	  2 messages
	  1 service
*/
package narf

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
	ModuleName = "narf"
	// VersionCrc is the CRC of this module.
	VersionCrc = 0xbe10a606
)

// NarfEnableDisable represents VPP binary API message 'narf_enable_disable'.
type NarfEnableDisable struct {
	EnableDisable uint8
	ServicePort   uint16
	SwIfIndex     uint32
}

func (*NarfEnableDisable) GetMessageName() string {
	return "narf_enable_disable"
}
func (*NarfEnableDisable) GetCrcString() string {
	return "ab092302"
}
func (*NarfEnableDisable) GetMessageType() api.MessageType {
	return api.RequestMessage
}

// NarfEnableDisableReply represents VPP binary API message 'narf_enable_disable_reply'.
type NarfEnableDisableReply struct {
	Retval int32
}

func (*NarfEnableDisableReply) GetMessageName() string {
	return "narf_enable_disable_reply"
}
func (*NarfEnableDisableReply) GetCrcString() string {
	return "e8d4e804"
}
func (*NarfEnableDisableReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}

func init() {
	api.RegisterMessage((*NarfEnableDisable)(nil), "narf.NarfEnableDisable")
	api.RegisterMessage((*NarfEnableDisableReply)(nil), "narf.NarfEnableDisableReply")
}

// Messages returns list of all messages in this module.
func AllMessages() []api.Message {
	return []api.Message{
		(*NarfEnableDisable)(nil),
		(*NarfEnableDisableReply)(nil),
	}
}

// RPCService represents RPC service API for narf module.
type RPCService interface {
	NarfEnableDisable(ctx context.Context, in *NarfEnableDisable) (*NarfEnableDisableReply, error)
}

type serviceClient struct {
	ch api.Channel
}

func NewServiceClient(ch api.Channel) RPCService {
	return &serviceClient{ch}
}

func (c *serviceClient) NarfEnableDisable(ctx context.Context, in *NarfEnableDisable) (*NarfEnableDisableReply, error) {
	out := new(NarfEnableDisableReply)
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
