// Code generated by GoVPP's binapi-generator. DO NOT EDIT.
// source: /usr/share/vpp/api/core/qos.api.json

/*
Package qos is a generated VPP binary API for 'qos' module.

It consists of:
	  1 enum
	  1 type
	  8 messages
	  4 services
*/
package qos

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
	ModuleName = "qos"
	// APIVersion is the API version of this module.
	APIVersion = "1.0.0"
	// VersionCrc is the CRC of this module.
	VersionCrc = 0xa23036b4
)

// QosSource represents VPP binary API enum 'qos_source'.
type QosSource uint32

const (
	QOS_API_SOURCE_EXT  QosSource = 0
	QOS_API_SOURCE_VLAN QosSource = 1
	QOS_API_SOURCE_MPLS QosSource = 2
	QOS_API_SOURCE_IP   QosSource = 3
)

var QosSource_name = map[uint32]string{
	0: "QOS_API_SOURCE_EXT",
	1: "QOS_API_SOURCE_VLAN",
	2: "QOS_API_SOURCE_MPLS",
	3: "QOS_API_SOURCE_IP",
}

var QosSource_value = map[string]uint32{
	"QOS_API_SOURCE_EXT":  0,
	"QOS_API_SOURCE_VLAN": 1,
	"QOS_API_SOURCE_MPLS": 2,
	"QOS_API_SOURCE_IP":   3,
}

func (x QosSource) String() string {
	s, ok := QosSource_name[uint32(x)]
	if ok {
		return s
	}
	return strconv.Itoa(int(x))
}

// QosEgressMapRow represents VPP binary API type 'qos_egress_map_row'.
type QosEgressMapRow struct {
	Outputs []byte `struc:"[256]byte"`
}

func (*QosEgressMapRow) GetTypeName() string {
	return "qos_egress_map_row"
}
func (*QosEgressMapRow) GetCrcString() string {
	return "d3bbaed6"
}

// QosEgressMapDelete represents VPP binary API message 'qos_egress_map_delete'.
type QosEgressMapDelete struct {
	MapID uint32
}

func (*QosEgressMapDelete) GetMessageName() string {
	return "qos_egress_map_delete"
}
func (*QosEgressMapDelete) GetCrcString() string {
	return "daab68c1"
}
func (*QosEgressMapDelete) GetMessageType() api.MessageType {
	return api.RequestMessage
}

// QosEgressMapDeleteReply represents VPP binary API message 'qos_egress_map_delete_reply'.
type QosEgressMapDeleteReply struct {
	Retval int32
}

func (*QosEgressMapDeleteReply) GetMessageName() string {
	return "qos_egress_map_delete_reply"
}
func (*QosEgressMapDeleteReply) GetCrcString() string {
	return "e8d4e804"
}
func (*QosEgressMapDeleteReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}

// QosEgressMapUpdate represents VPP binary API message 'qos_egress_map_update'.
type QosEgressMapUpdate struct {
	MapID uint32
	Rows  []QosEgressMapRow `struc:"[4]QosEgressMapRow"`
}

func (*QosEgressMapUpdate) GetMessageName() string {
	return "qos_egress_map_update"
}
func (*QosEgressMapUpdate) GetCrcString() string {
	return "5d5c3cad"
}
func (*QosEgressMapUpdate) GetMessageType() api.MessageType {
	return api.RequestMessage
}

// QosEgressMapUpdateReply represents VPP binary API message 'qos_egress_map_update_reply'.
type QosEgressMapUpdateReply struct {
	Retval int32
}

func (*QosEgressMapUpdateReply) GetMessageName() string {
	return "qos_egress_map_update_reply"
}
func (*QosEgressMapUpdateReply) GetCrcString() string {
	return "e8d4e804"
}
func (*QosEgressMapUpdateReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}

// QosMarkEnableDisable represents VPP binary API message 'qos_mark_enable_disable'.
type QosMarkEnableDisable struct {
	MapID        uint32
	SwIfIndex    uint32
	OutputSource QosSource
	Enable       uint8
}

func (*QosMarkEnableDisable) GetMessageName() string {
	return "qos_mark_enable_disable"
}
func (*QosMarkEnableDisable) GetCrcString() string {
	return "3990ab06"
}
func (*QosMarkEnableDisable) GetMessageType() api.MessageType {
	return api.RequestMessage
}

// QosMarkEnableDisableReply represents VPP binary API message 'qos_mark_enable_disable_reply'.
type QosMarkEnableDisableReply struct {
	Retval int32
}

func (*QosMarkEnableDisableReply) GetMessageName() string {
	return "qos_mark_enable_disable_reply"
}
func (*QosMarkEnableDisableReply) GetCrcString() string {
	return "e8d4e804"
}
func (*QosMarkEnableDisableReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}

// QosRecordEnableDisable represents VPP binary API message 'qos_record_enable_disable'.
type QosRecordEnableDisable struct {
	SwIfIndex   uint32
	InputSource QosSource
	Enable      uint8
}

func (*QosRecordEnableDisable) GetMessageName() string {
	return "qos_record_enable_disable"
}
func (*QosRecordEnableDisable) GetCrcString() string {
	return "f768050f"
}
func (*QosRecordEnableDisable) GetMessageType() api.MessageType {
	return api.RequestMessage
}

// QosRecordEnableDisableReply represents VPP binary API message 'qos_record_enable_disable_reply'.
type QosRecordEnableDisableReply struct {
	Retval int32
}

func (*QosRecordEnableDisableReply) GetMessageName() string {
	return "qos_record_enable_disable_reply"
}
func (*QosRecordEnableDisableReply) GetCrcString() string {
	return "e8d4e804"
}
func (*QosRecordEnableDisableReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}

func init() {
	api.RegisterMessage((*QosEgressMapDelete)(nil), "qos.QosEgressMapDelete")
	api.RegisterMessage((*QosEgressMapDeleteReply)(nil), "qos.QosEgressMapDeleteReply")
	api.RegisterMessage((*QosEgressMapUpdate)(nil), "qos.QosEgressMapUpdate")
	api.RegisterMessage((*QosEgressMapUpdateReply)(nil), "qos.QosEgressMapUpdateReply")
	api.RegisterMessage((*QosMarkEnableDisable)(nil), "qos.QosMarkEnableDisable")
	api.RegisterMessage((*QosMarkEnableDisableReply)(nil), "qos.QosMarkEnableDisableReply")
	api.RegisterMessage((*QosRecordEnableDisable)(nil), "qos.QosRecordEnableDisable")
	api.RegisterMessage((*QosRecordEnableDisableReply)(nil), "qos.QosRecordEnableDisableReply")
}

// Messages returns list of all messages in this module.
func AllMessages() []api.Message {
	return []api.Message{
		(*QosEgressMapDelete)(nil),
		(*QosEgressMapDeleteReply)(nil),
		(*QosEgressMapUpdate)(nil),
		(*QosEgressMapUpdateReply)(nil),
		(*QosMarkEnableDisable)(nil),
		(*QosMarkEnableDisableReply)(nil),
		(*QosRecordEnableDisable)(nil),
		(*QosRecordEnableDisableReply)(nil),
	}
}

// RPCService represents RPC service API for qos module.
type RPCService interface {
	QosEgressMapDelete(ctx context.Context, in *QosEgressMapDelete) (*QosEgressMapDeleteReply, error)
	QosEgressMapUpdate(ctx context.Context, in *QosEgressMapUpdate) (*QosEgressMapUpdateReply, error)
	QosMarkEnableDisable(ctx context.Context, in *QosMarkEnableDisable) (*QosMarkEnableDisableReply, error)
	QosRecordEnableDisable(ctx context.Context, in *QosRecordEnableDisable) (*QosRecordEnableDisableReply, error)
}

type serviceClient struct {
	ch api.Channel
}

func NewServiceClient(ch api.Channel) RPCService {
	return &serviceClient{ch}
}

func (c *serviceClient) QosEgressMapDelete(ctx context.Context, in *QosEgressMapDelete) (*QosEgressMapDeleteReply, error) {
	out := new(QosEgressMapDeleteReply)
	err := c.ch.SendRequest(in).ReceiveReply(out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serviceClient) QosEgressMapUpdate(ctx context.Context, in *QosEgressMapUpdate) (*QosEgressMapUpdateReply, error) {
	out := new(QosEgressMapUpdateReply)
	err := c.ch.SendRequest(in).ReceiveReply(out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serviceClient) QosMarkEnableDisable(ctx context.Context, in *QosMarkEnableDisable) (*QosMarkEnableDisableReply, error) {
	out := new(QosMarkEnableDisableReply)
	err := c.ch.SendRequest(in).ReceiveReply(out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serviceClient) QosRecordEnableDisable(ctx context.Context, in *QosRecordEnableDisable) (*QosRecordEnableDisableReply, error) {
	out := new(QosRecordEnableDisableReply)
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
