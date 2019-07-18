// Code generated by GoVPP's binapi-generator. DO NOT EDIT.
// source: /usr/share/vpp/api/plugins/svs.api.json

/*
Package svs is a generated VPP binary API for 'svs' module.

It consists of:
	  1 enum
	  2 aliases
	  5 types
	  1 union
	 10 messages
	  5 services
*/
package svs

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
	ModuleName = "svs"
	// APIVersion is the API version of this module.
	APIVersion = "1.0.0"
	// VersionCrc is the CRC of this module.
	VersionCrc = 0x190106df
)

// AddressFamily represents VPP binary API enum 'address_family'.
type AddressFamily uint32

const (
	ADDRESS_IP4 AddressFamily = 0
	ADDRESS_IP6 AddressFamily = 1
)

var AddressFamily_name = map[uint32]string{
	0: "ADDRESS_IP4",
	1: "ADDRESS_IP6",
}

var AddressFamily_value = map[string]uint32{
	"ADDRESS_IP4": 0,
	"ADDRESS_IP6": 1,
}

func (x AddressFamily) String() string {
	s, ok := AddressFamily_name[uint32(x)]
	if ok {
		return s
	}
	return strconv.Itoa(int(x))
}

// IP4Address represents VPP binary API alias 'ip4_address'.
type IP4Address [4]uint8

// IP6Address represents VPP binary API alias 'ip6_address'.
type IP6Address [16]uint8

// Address represents VPP binary API type 'address'.
type Address struct {
	Af AddressFamily
	Un AddressUnion
}

func (*Address) GetTypeName() string {
	return "address"
}
func (*Address) GetCrcString() string {
	return "09f11671"
}

// IP4Prefix represents VPP binary API type 'ip4_prefix'.
type IP4Prefix struct {
	Prefix IP4Address
	Len    uint8
}

func (*IP4Prefix) GetTypeName() string {
	return "ip4_prefix"
}
func (*IP4Prefix) GetCrcString() string {
	return "ea8dc11d"
}

// IP6Prefix represents VPP binary API type 'ip6_prefix'.
type IP6Prefix struct {
	Prefix IP6Address
	Len    uint8
}

func (*IP6Prefix) GetTypeName() string {
	return "ip6_prefix"
}
func (*IP6Prefix) GetCrcString() string {
	return "779fd64f"
}

// Mprefix represents VPP binary API type 'mprefix'.
type Mprefix struct {
	Af               AddressFamily
	GrpAddressLength uint16
	GrpAddress       AddressUnion
	SrcAddress       AddressUnion
}

func (*Mprefix) GetTypeName() string {
	return "mprefix"
}
func (*Mprefix) GetCrcString() string {
	return "1c4cba05"
}

// Prefix represents VPP binary API type 'prefix'.
type Prefix struct {
	Address       Address
	AddressLength uint8
}

func (*Prefix) GetTypeName() string {
	return "prefix"
}
func (*Prefix) GetCrcString() string {
	return "0403aebc"
}

// AddressUnion represents VPP binary API union 'address_union'.
type AddressUnion struct {
	XXX_UnionData [16]byte
}

func (*AddressUnion) GetTypeName() string {
	return "address_union"
}
func (*AddressUnion) GetCrcString() string {
	return "d68a2fb4"
}

func AddressUnionIP4(a IP4Address) (u AddressUnion) {
	u.SetIP4(a)
	return
}
func (u *AddressUnion) SetIP4(a IP4Address) {
	var b = new(bytes.Buffer)
	if err := struc.Pack(b, &a); err != nil {
		return
	}
	copy(u.XXX_UnionData[:], b.Bytes())
}
func (u *AddressUnion) GetIP4() (a IP4Address) {
	var b = bytes.NewReader(u.XXX_UnionData[:])
	struc.Unpack(b, &a)
	return
}

func AddressUnionIP6(a IP6Address) (u AddressUnion) {
	u.SetIP6(a)
	return
}
func (u *AddressUnion) SetIP6(a IP6Address) {
	var b = new(bytes.Buffer)
	if err := struc.Pack(b, &a); err != nil {
		return
	}
	copy(u.XXX_UnionData[:], b.Bytes())
}
func (u *AddressUnion) GetIP6() (a IP6Address) {
	var b = bytes.NewReader(u.XXX_UnionData[:])
	struc.Unpack(b, &a)
	return
}

// SvsDetails represents VPP binary API message 'svs_details'.
type SvsDetails struct {
	TableID   uint32
	SwIfIndex uint32
	Af        AddressFamily
}

func (*SvsDetails) GetMessageName() string {
	return "svs_details"
}
func (*SvsDetails) GetCrcString() string {
	return "2a7c7411"
}
func (*SvsDetails) GetMessageType() api.MessageType {
	return api.ReplyMessage
}

// SvsDump represents VPP binary API message 'svs_dump'.
type SvsDump struct{}

func (*SvsDump) GetMessageName() string {
	return "svs_dump"
}
func (*SvsDump) GetCrcString() string {
	return "51077d14"
}
func (*SvsDump) GetMessageType() api.MessageType {
	return api.RequestMessage
}

// SvsEnableDisable represents VPP binary API message 'svs_enable_disable'.
type SvsEnableDisable struct {
	IsEnable  uint8
	Af        AddressFamily
	TableID   uint32
	SwIfIndex uint32
}

func (*SvsEnableDisable) GetMessageName() string {
	return "svs_enable_disable"
}
func (*SvsEnableDisable) GetCrcString() string {
	return "bfd387a2"
}
func (*SvsEnableDisable) GetMessageType() api.MessageType {
	return api.RequestMessage
}

// SvsEnableDisableReply represents VPP binary API message 'svs_enable_disable_reply'.
type SvsEnableDisableReply struct {
	Retval int32
}

func (*SvsEnableDisableReply) GetMessageName() string {
	return "svs_enable_disable_reply"
}
func (*SvsEnableDisableReply) GetCrcString() string {
	return "e8d4e804"
}
func (*SvsEnableDisableReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}

// SvsPluginGetVersion represents VPP binary API message 'svs_plugin_get_version'.
type SvsPluginGetVersion struct{}

func (*SvsPluginGetVersion) GetMessageName() string {
	return "svs_plugin_get_version"
}
func (*SvsPluginGetVersion) GetCrcString() string {
	return "51077d14"
}
func (*SvsPluginGetVersion) GetMessageType() api.MessageType {
	return api.RequestMessage
}

// SvsPluginGetVersionReply represents VPP binary API message 'svs_plugin_get_version_reply'.
type SvsPluginGetVersionReply struct {
	Major uint32
	Minor uint32
}

func (*SvsPluginGetVersionReply) GetMessageName() string {
	return "svs_plugin_get_version_reply"
}
func (*SvsPluginGetVersionReply) GetCrcString() string {
	return "9b32cf86"
}
func (*SvsPluginGetVersionReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}

// SvsRouteAddDel represents VPP binary API message 'svs_route_add_del'.
type SvsRouteAddDel struct {
	IsAdd         uint8
	Prefix        Prefix
	TableID       uint32
	SourceTableID uint32
}

func (*SvsRouteAddDel) GetMessageName() string {
	return "svs_route_add_del"
}
func (*SvsRouteAddDel) GetCrcString() string {
	return "dc122202"
}
func (*SvsRouteAddDel) GetMessageType() api.MessageType {
	return api.RequestMessage
}

// SvsRouteAddDelReply represents VPP binary API message 'svs_route_add_del_reply'.
type SvsRouteAddDelReply struct {
	Retval int32
}

func (*SvsRouteAddDelReply) GetMessageName() string {
	return "svs_route_add_del_reply"
}
func (*SvsRouteAddDelReply) GetCrcString() string {
	return "e8d4e804"
}
func (*SvsRouteAddDelReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}

// SvsTableAddDel represents VPP binary API message 'svs_table_add_del'.
type SvsTableAddDel struct {
	IsAdd   uint8
	Af      AddressFamily
	TableID uint32
}

func (*SvsTableAddDel) GetMessageName() string {
	return "svs_table_add_del"
}
func (*SvsTableAddDel) GetCrcString() string {
	return "3b28c790"
}
func (*SvsTableAddDel) GetMessageType() api.MessageType {
	return api.RequestMessage
}

// SvsTableAddDelReply represents VPP binary API message 'svs_table_add_del_reply'.
type SvsTableAddDelReply struct {
	Retval int32
}

func (*SvsTableAddDelReply) GetMessageName() string {
	return "svs_table_add_del_reply"
}
func (*SvsTableAddDelReply) GetCrcString() string {
	return "e8d4e804"
}
func (*SvsTableAddDelReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}

func init() {
	api.RegisterMessage((*SvsDetails)(nil), "svs.SvsDetails")
	api.RegisterMessage((*SvsDump)(nil), "svs.SvsDump")
	api.RegisterMessage((*SvsEnableDisable)(nil), "svs.SvsEnableDisable")
	api.RegisterMessage((*SvsEnableDisableReply)(nil), "svs.SvsEnableDisableReply")
	api.RegisterMessage((*SvsPluginGetVersion)(nil), "svs.SvsPluginGetVersion")
	api.RegisterMessage((*SvsPluginGetVersionReply)(nil), "svs.SvsPluginGetVersionReply")
	api.RegisterMessage((*SvsRouteAddDel)(nil), "svs.SvsRouteAddDel")
	api.RegisterMessage((*SvsRouteAddDelReply)(nil), "svs.SvsRouteAddDelReply")
	api.RegisterMessage((*SvsTableAddDel)(nil), "svs.SvsTableAddDel")
	api.RegisterMessage((*SvsTableAddDelReply)(nil), "svs.SvsTableAddDelReply")
}

// Messages returns list of all messages in this module.
func AllMessages() []api.Message {
	return []api.Message{
		(*SvsDetails)(nil),
		(*SvsDump)(nil),
		(*SvsEnableDisable)(nil),
		(*SvsEnableDisableReply)(nil),
		(*SvsPluginGetVersion)(nil),
		(*SvsPluginGetVersionReply)(nil),
		(*SvsRouteAddDel)(nil),
		(*SvsRouteAddDelReply)(nil),
		(*SvsTableAddDel)(nil),
		(*SvsTableAddDelReply)(nil),
	}
}

// RPCService represents RPC service API for svs module.
type RPCService interface {
	DumpSvs(ctx context.Context, in *SvsDump) (RPCService_DumpSvsClient, error)
	SvsEnableDisable(ctx context.Context, in *SvsEnableDisable) (*SvsEnableDisableReply, error)
	SvsPluginGetVersion(ctx context.Context, in *SvsPluginGetVersion) (*SvsPluginGetVersionReply, error)
	SvsRouteAddDel(ctx context.Context, in *SvsRouteAddDel) (*SvsRouteAddDelReply, error)
	SvsTableAddDel(ctx context.Context, in *SvsTableAddDel) (*SvsTableAddDelReply, error)
}

type serviceClient struct {
	ch api.Channel
}

func NewServiceClient(ch api.Channel) RPCService {
	return &serviceClient{ch}
}

func (c *serviceClient) DumpSvs(ctx context.Context, in *SvsDump) (RPCService_DumpSvsClient, error) {
	stream := c.ch.SendMultiRequest(in)
	x := &serviceClient_DumpSvsClient{stream}
	return x, nil
}

type RPCService_DumpSvsClient interface {
	Recv() (*SvsDetails, error)
}

type serviceClient_DumpSvsClient struct {
	api.MultiRequestCtx
}

func (c *serviceClient_DumpSvsClient) Recv() (*SvsDetails, error) {
	m := new(SvsDetails)
	stop, err := c.MultiRequestCtx.ReceiveReply(m)
	if err != nil {
		return nil, err
	}
	if stop {
		return nil, io.EOF
	}
	return m, nil
}

func (c *serviceClient) SvsEnableDisable(ctx context.Context, in *SvsEnableDisable) (*SvsEnableDisableReply, error) {
	out := new(SvsEnableDisableReply)
	err := c.ch.SendRequest(in).ReceiveReply(out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serviceClient) SvsPluginGetVersion(ctx context.Context, in *SvsPluginGetVersion) (*SvsPluginGetVersionReply, error) {
	out := new(SvsPluginGetVersionReply)
	err := c.ch.SendRequest(in).ReceiveReply(out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serviceClient) SvsRouteAddDel(ctx context.Context, in *SvsRouteAddDel) (*SvsRouteAddDelReply, error) {
	out := new(SvsRouteAddDelReply)
	err := c.ch.SendRequest(in).ReceiveReply(out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serviceClient) SvsTableAddDel(ctx context.Context, in *SvsTableAddDel) (*SvsTableAddDelReply, error) {
	out := new(SvsTableAddDelReply)
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
