// Code generated by GoVPP's binapi-generator. DO NOT EDIT.
// source: /usr/share/vpp/api/plugins/vxlan_gpe_ioam_export.api.json

/*
Package vxlan_gpe_ioam_export is a generated VPP binary API for 'vxlan_gpe_ioam_export' module.

It consists of:
	  2 messages
	  1 service
*/
package vxlan_gpe_ioam_export

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
	ModuleName = "vxlan_gpe_ioam_export"
	// APIVersion is the API version of this module.
	APIVersion = "1.0.0"
	// VersionCrc is the CRC of this module.
	VersionCrc = 0x22132a2c
)

// VxlanGpeIoamExportEnableDisable represents VPP binary API message 'vxlan_gpe_ioam_export_enable_disable'.
type VxlanGpeIoamExportEnableDisable struct {
	IsDisable        uint8
	CollectorAddress []byte `struc:"[4]byte"`
	SrcAddress       []byte `struc:"[4]byte"`
}

func (*VxlanGpeIoamExportEnableDisable) GetMessageName() string {
	return "vxlan_gpe_ioam_export_enable_disable"
}
func (*VxlanGpeIoamExportEnableDisable) GetCrcString() string {
	return "148b82a4"
}
func (*VxlanGpeIoamExportEnableDisable) GetMessageType() api.MessageType {
	return api.RequestMessage
}

// VxlanGpeIoamExportEnableDisableReply represents VPP binary API message 'vxlan_gpe_ioam_export_enable_disable_reply'.
type VxlanGpeIoamExportEnableDisableReply struct {
	Retval int32
}

func (*VxlanGpeIoamExportEnableDisableReply) GetMessageName() string {
	return "vxlan_gpe_ioam_export_enable_disable_reply"
}
func (*VxlanGpeIoamExportEnableDisableReply) GetCrcString() string {
	return "e8d4e804"
}
func (*VxlanGpeIoamExportEnableDisableReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}

func init() {
	api.RegisterMessage((*VxlanGpeIoamExportEnableDisable)(nil), "vxlan_gpe_ioam_export.VxlanGpeIoamExportEnableDisable")
	api.RegisterMessage((*VxlanGpeIoamExportEnableDisableReply)(nil), "vxlan_gpe_ioam_export.VxlanGpeIoamExportEnableDisableReply")
}

// Messages returns list of all messages in this module.
func AllMessages() []api.Message {
	return []api.Message{
		(*VxlanGpeIoamExportEnableDisable)(nil),
		(*VxlanGpeIoamExportEnableDisableReply)(nil),
	}
}

// RPCService represents RPC service API for vxlan_gpe_ioam_export module.
type RPCService interface {
	VxlanGpeIoamExportEnableDisable(ctx context.Context, in *VxlanGpeIoamExportEnableDisable) (*VxlanGpeIoamExportEnableDisableReply, error)
}

type serviceClient struct {
	ch api.Channel
}

func NewServiceClient(ch api.Channel) RPCService {
	return &serviceClient{ch}
}

func (c *serviceClient) VxlanGpeIoamExportEnableDisable(ctx context.Context, in *VxlanGpeIoamExportEnableDisable) (*VxlanGpeIoamExportEnableDisableReply, error) {
	out := new(VxlanGpeIoamExportEnableDisableReply)
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
