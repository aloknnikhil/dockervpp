// Code generated by GoVPP's binapi-generator. DO NOT EDIT.
// source: /usr/share/vpp/api/core/classify.api.json

/*
Package classify is a generated VPP binary API for 'classify' module.

It consists of:
	 28 messages
	 14 services
*/
package classify

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
	ModuleName = "classify"
	// APIVersion is the API version of this module.
	APIVersion = "2.0.0"
	// VersionCrc is the CRC of this module.
	VersionCrc = 0x75a3c89c
)

// ClassifyAddDelSession represents VPP binary API message 'classify_add_del_session'.
type ClassifyAddDelSession struct {
	IsAdd        uint8
	TableIndex   uint32
	HitNextIndex uint32
	OpaqueIndex  uint32
	Advance      int32
	Action       uint8
	Metadata     uint32
	MatchLen     uint32 `struc:"sizeof=Match"`
	Match        []byte
}

func (*ClassifyAddDelSession) GetMessageName() string {
	return "classify_add_del_session"
}
func (*ClassifyAddDelSession) GetCrcString() string {
	return "85fd79f4"
}
func (*ClassifyAddDelSession) GetMessageType() api.MessageType {
	return api.RequestMessage
}

// ClassifyAddDelSessionReply represents VPP binary API message 'classify_add_del_session_reply'.
type ClassifyAddDelSessionReply struct {
	Retval int32
}

func (*ClassifyAddDelSessionReply) GetMessageName() string {
	return "classify_add_del_session_reply"
}
func (*ClassifyAddDelSessionReply) GetCrcString() string {
	return "e8d4e804"
}
func (*ClassifyAddDelSessionReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}

// ClassifyAddDelTable represents VPP binary API message 'classify_add_del_table'.
type ClassifyAddDelTable struct {
	IsAdd             uint8
	DelChain          uint8
	TableIndex        uint32
	Nbuckets          uint32
	MemorySize        uint32
	SkipNVectors      uint32
	MatchNVectors     uint32
	NextTableIndex    uint32
	MissNextIndex     uint32
	CurrentDataFlag   uint32
	CurrentDataOffset int32
	MaskLen           uint32 `struc:"sizeof=Mask"`
	Mask              []byte
}

func (*ClassifyAddDelTable) GetMessageName() string {
	return "classify_add_del_table"
}
func (*ClassifyAddDelTable) GetCrcString() string {
	return "9bd794ae"
}
func (*ClassifyAddDelTable) GetMessageType() api.MessageType {
	return api.RequestMessage
}

// ClassifyAddDelTableReply represents VPP binary API message 'classify_add_del_table_reply'.
type ClassifyAddDelTableReply struct {
	Retval        int32
	NewTableIndex uint32
	SkipNVectors  uint32
	MatchNVectors uint32
}

func (*ClassifyAddDelTableReply) GetMessageName() string {
	return "classify_add_del_table_reply"
}
func (*ClassifyAddDelTableReply) GetCrcString() string {
	return "05486349"
}
func (*ClassifyAddDelTableReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}

// ClassifySessionDetails represents VPP binary API message 'classify_session_details'.
type ClassifySessionDetails struct {
	Retval       int32
	TableID      uint32
	HitNextIndex uint32
	Advance      int32
	OpaqueIndex  uint32
	MatchLength  uint32 `struc:"sizeof=Match"`
	Match        []byte
}

func (*ClassifySessionDetails) GetMessageName() string {
	return "classify_session_details"
}
func (*ClassifySessionDetails) GetCrcString() string {
	return "60e3ef94"
}
func (*ClassifySessionDetails) GetMessageType() api.MessageType {
	return api.ReplyMessage
}

// ClassifySessionDump represents VPP binary API message 'classify_session_dump'.
type ClassifySessionDump struct {
	TableID uint32
}

func (*ClassifySessionDump) GetMessageName() string {
	return "classify_session_dump"
}
func (*ClassifySessionDump) GetCrcString() string {
	return "0cca2cd9"
}
func (*ClassifySessionDump) GetMessageType() api.MessageType {
	return api.RequestMessage
}

// ClassifySetInterfaceIPTable represents VPP binary API message 'classify_set_interface_ip_table'.
type ClassifySetInterfaceIPTable struct {
	IsIPv6     uint8
	SwIfIndex  uint32
	TableIndex uint32
}

func (*ClassifySetInterfaceIPTable) GetMessageName() string {
	return "classify_set_interface_ip_table"
}
func (*ClassifySetInterfaceIPTable) GetCrcString() string {
	return "d7199b03"
}
func (*ClassifySetInterfaceIPTable) GetMessageType() api.MessageType {
	return api.RequestMessage
}

// ClassifySetInterfaceIPTableReply represents VPP binary API message 'classify_set_interface_ip_table_reply'.
type ClassifySetInterfaceIPTableReply struct {
	Retval int32
}

func (*ClassifySetInterfaceIPTableReply) GetMessageName() string {
	return "classify_set_interface_ip_table_reply"
}
func (*ClassifySetInterfaceIPTableReply) GetCrcString() string {
	return "e8d4e804"
}
func (*ClassifySetInterfaceIPTableReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}

// ClassifySetInterfaceL2Tables represents VPP binary API message 'classify_set_interface_l2_tables'.
type ClassifySetInterfaceL2Tables struct {
	SwIfIndex       uint32
	IP4TableIndex   uint32
	IP6TableIndex   uint32
	OtherTableIndex uint32
	IsInput         uint8
}

func (*ClassifySetInterfaceL2Tables) GetMessageName() string {
	return "classify_set_interface_l2_tables"
}
func (*ClassifySetInterfaceL2Tables) GetCrcString() string {
	return "6d60ab5f"
}
func (*ClassifySetInterfaceL2Tables) GetMessageType() api.MessageType {
	return api.RequestMessage
}

// ClassifySetInterfaceL2TablesReply represents VPP binary API message 'classify_set_interface_l2_tables_reply'.
type ClassifySetInterfaceL2TablesReply struct {
	Retval int32
}

func (*ClassifySetInterfaceL2TablesReply) GetMessageName() string {
	return "classify_set_interface_l2_tables_reply"
}
func (*ClassifySetInterfaceL2TablesReply) GetCrcString() string {
	return "e8d4e804"
}
func (*ClassifySetInterfaceL2TablesReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}

// ClassifyTableByInterface represents VPP binary API message 'classify_table_by_interface'.
type ClassifyTableByInterface struct {
	SwIfIndex uint32
}

func (*ClassifyTableByInterface) GetMessageName() string {
	return "classify_table_by_interface"
}
func (*ClassifyTableByInterface) GetCrcString() string {
	return "529cb13f"
}
func (*ClassifyTableByInterface) GetMessageType() api.MessageType {
	return api.RequestMessage
}

// ClassifyTableByInterfaceReply represents VPP binary API message 'classify_table_by_interface_reply'.
type ClassifyTableByInterfaceReply struct {
	Retval     int32
	SwIfIndex  uint32
	L2TableID  uint32
	IP4TableID uint32
	IP6TableID uint32
}

func (*ClassifyTableByInterfaceReply) GetMessageName() string {
	return "classify_table_by_interface_reply"
}
func (*ClassifyTableByInterfaceReply) GetCrcString() string {
	return "eccde823"
}
func (*ClassifyTableByInterfaceReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}

// ClassifyTableIds represents VPP binary API message 'classify_table_ids'.
type ClassifyTableIds struct{}

func (*ClassifyTableIds) GetMessageName() string {
	return "classify_table_ids"
}
func (*ClassifyTableIds) GetCrcString() string {
	return "51077d14"
}
func (*ClassifyTableIds) GetMessageType() api.MessageType {
	return api.RequestMessage
}

// ClassifyTableIdsReply represents VPP binary API message 'classify_table_ids_reply'.
type ClassifyTableIdsReply struct {
	Retval int32
	Count  uint32 `struc:"sizeof=Ids"`
	Ids    []uint32
}

func (*ClassifyTableIdsReply) GetMessageName() string {
	return "classify_table_ids_reply"
}
func (*ClassifyTableIdsReply) GetCrcString() string {
	return "d1d20e1d"
}
func (*ClassifyTableIdsReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}

// ClassifyTableInfo represents VPP binary API message 'classify_table_info'.
type ClassifyTableInfo struct {
	TableID uint32
}

func (*ClassifyTableInfo) GetMessageName() string {
	return "classify_table_info"
}
func (*ClassifyTableInfo) GetCrcString() string {
	return "0cca2cd9"
}
func (*ClassifyTableInfo) GetMessageType() api.MessageType {
	return api.RequestMessage
}

// ClassifyTableInfoReply represents VPP binary API message 'classify_table_info_reply'.
type ClassifyTableInfoReply struct {
	Retval         int32
	TableID        uint32
	Nbuckets       uint32
	MatchNVectors  uint32
	SkipNVectors   uint32
	ActiveSessions uint32
	NextTableIndex uint32
	MissNextIndex  uint32
	MaskLength     uint32 `struc:"sizeof=Mask"`
	Mask           []byte
}

func (*ClassifyTableInfoReply) GetMessageName() string {
	return "classify_table_info_reply"
}
func (*ClassifyTableInfoReply) GetCrcString() string {
	return "4a573c0e"
}
func (*ClassifyTableInfoReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}

// FlowClassifyDetails represents VPP binary API message 'flow_classify_details'.
type FlowClassifyDetails struct {
	SwIfIndex  uint32
	TableIndex uint32
}

func (*FlowClassifyDetails) GetMessageName() string {
	return "flow_classify_details"
}
func (*FlowClassifyDetails) GetCrcString() string {
	return "cc3461ad"
}
func (*FlowClassifyDetails) GetMessageType() api.MessageType {
	return api.ReplyMessage
}

// FlowClassifyDump represents VPP binary API message 'flow_classify_dump'.
type FlowClassifyDump struct {
	Type uint8
}

func (*FlowClassifyDump) GetMessageName() string {
	return "flow_classify_dump"
}
func (*FlowClassifyDump) GetCrcString() string {
	return "41503530"
}
func (*FlowClassifyDump) GetMessageType() api.MessageType {
	return api.RequestMessage
}

// FlowClassifySetInterface represents VPP binary API message 'flow_classify_set_interface'.
type FlowClassifySetInterface struct {
	SwIfIndex     uint32
	IP4TableIndex uint32
	IP6TableIndex uint32
	IsAdd         uint8
}

func (*FlowClassifySetInterface) GetMessageName() string {
	return "flow_classify_set_interface"
}
func (*FlowClassifySetInterface) GetCrcString() string {
	return "275fa12c"
}
func (*FlowClassifySetInterface) GetMessageType() api.MessageType {
	return api.RequestMessage
}

// FlowClassifySetInterfaceReply represents VPP binary API message 'flow_classify_set_interface_reply'.
type FlowClassifySetInterfaceReply struct {
	Retval int32
}

func (*FlowClassifySetInterfaceReply) GetMessageName() string {
	return "flow_classify_set_interface_reply"
}
func (*FlowClassifySetInterfaceReply) GetCrcString() string {
	return "e8d4e804"
}
func (*FlowClassifySetInterfaceReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}

// InputACLSetInterface represents VPP binary API message 'input_acl_set_interface'.
type InputACLSetInterface struct {
	SwIfIndex     uint32
	IP4TableIndex uint32
	IP6TableIndex uint32
	L2TableIndex  uint32
	IsAdd         uint8
}

func (*InputACLSetInterface) GetMessageName() string {
	return "input_acl_set_interface"
}
func (*InputACLSetInterface) GetCrcString() string {
	return "e09537b0"
}
func (*InputACLSetInterface) GetMessageType() api.MessageType {
	return api.RequestMessage
}

// InputACLSetInterfaceReply represents VPP binary API message 'input_acl_set_interface_reply'.
type InputACLSetInterfaceReply struct {
	Retval int32
}

func (*InputACLSetInterfaceReply) GetMessageName() string {
	return "input_acl_set_interface_reply"
}
func (*InputACLSetInterfaceReply) GetCrcString() string {
	return "e8d4e804"
}
func (*InputACLSetInterfaceReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}

// OutputACLSetInterface represents VPP binary API message 'output_acl_set_interface'.
type OutputACLSetInterface struct {
	SwIfIndex     uint32
	IP4TableIndex uint32
	IP6TableIndex uint32
	L2TableIndex  uint32
	IsAdd         uint8
}

func (*OutputACLSetInterface) GetMessageName() string {
	return "output_acl_set_interface"
}
func (*OutputACLSetInterface) GetCrcString() string {
	return "e09537b0"
}
func (*OutputACLSetInterface) GetMessageType() api.MessageType {
	return api.RequestMessage
}

// OutputACLSetInterfaceReply represents VPP binary API message 'output_acl_set_interface_reply'.
type OutputACLSetInterfaceReply struct {
	Retval int32
}

func (*OutputACLSetInterfaceReply) GetMessageName() string {
	return "output_acl_set_interface_reply"
}
func (*OutputACLSetInterfaceReply) GetCrcString() string {
	return "e8d4e804"
}
func (*OutputACLSetInterfaceReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}

// PolicerClassifyDetails represents VPP binary API message 'policer_classify_details'.
type PolicerClassifyDetails struct {
	SwIfIndex  uint32
	TableIndex uint32
}

func (*PolicerClassifyDetails) GetMessageName() string {
	return "policer_classify_details"
}
func (*PolicerClassifyDetails) GetCrcString() string {
	return "cc3461ad"
}
func (*PolicerClassifyDetails) GetMessageType() api.MessageType {
	return api.ReplyMessage
}

// PolicerClassifyDump represents VPP binary API message 'policer_classify_dump'.
type PolicerClassifyDump struct {
	Type uint8
}

func (*PolicerClassifyDump) GetMessageName() string {
	return "policer_classify_dump"
}
func (*PolicerClassifyDump) GetCrcString() string {
	return "41503530"
}
func (*PolicerClassifyDump) GetMessageType() api.MessageType {
	return api.RequestMessage
}

// PolicerClassifySetInterface represents VPP binary API message 'policer_classify_set_interface'.
type PolicerClassifySetInterface struct {
	SwIfIndex     uint32
	IP4TableIndex uint32
	IP6TableIndex uint32
	L2TableIndex  uint32
	IsAdd         uint8
}

func (*PolicerClassifySetInterface) GetMessageName() string {
	return "policer_classify_set_interface"
}
func (*PolicerClassifySetInterface) GetCrcString() string {
	return "e09537b0"
}
func (*PolicerClassifySetInterface) GetMessageType() api.MessageType {
	return api.RequestMessage
}

// PolicerClassifySetInterfaceReply represents VPP binary API message 'policer_classify_set_interface_reply'.
type PolicerClassifySetInterfaceReply struct {
	Retval int32
}

func (*PolicerClassifySetInterfaceReply) GetMessageName() string {
	return "policer_classify_set_interface_reply"
}
func (*PolicerClassifySetInterfaceReply) GetCrcString() string {
	return "e8d4e804"
}
func (*PolicerClassifySetInterfaceReply) GetMessageType() api.MessageType {
	return api.ReplyMessage
}

func init() {
	api.RegisterMessage((*ClassifyAddDelSession)(nil), "classify.ClassifyAddDelSession")
	api.RegisterMessage((*ClassifyAddDelSessionReply)(nil), "classify.ClassifyAddDelSessionReply")
	api.RegisterMessage((*ClassifyAddDelTable)(nil), "classify.ClassifyAddDelTable")
	api.RegisterMessage((*ClassifyAddDelTableReply)(nil), "classify.ClassifyAddDelTableReply")
	api.RegisterMessage((*ClassifySessionDetails)(nil), "classify.ClassifySessionDetails")
	api.RegisterMessage((*ClassifySessionDump)(nil), "classify.ClassifySessionDump")
	api.RegisterMessage((*ClassifySetInterfaceIPTable)(nil), "classify.ClassifySetInterfaceIPTable")
	api.RegisterMessage((*ClassifySetInterfaceIPTableReply)(nil), "classify.ClassifySetInterfaceIPTableReply")
	api.RegisterMessage((*ClassifySetInterfaceL2Tables)(nil), "classify.ClassifySetInterfaceL2Tables")
	api.RegisterMessage((*ClassifySetInterfaceL2TablesReply)(nil), "classify.ClassifySetInterfaceL2TablesReply")
	api.RegisterMessage((*ClassifyTableByInterface)(nil), "classify.ClassifyTableByInterface")
	api.RegisterMessage((*ClassifyTableByInterfaceReply)(nil), "classify.ClassifyTableByInterfaceReply")
	api.RegisterMessage((*ClassifyTableIds)(nil), "classify.ClassifyTableIds")
	api.RegisterMessage((*ClassifyTableIdsReply)(nil), "classify.ClassifyTableIdsReply")
	api.RegisterMessage((*ClassifyTableInfo)(nil), "classify.ClassifyTableInfo")
	api.RegisterMessage((*ClassifyTableInfoReply)(nil), "classify.ClassifyTableInfoReply")
	api.RegisterMessage((*FlowClassifyDetails)(nil), "classify.FlowClassifyDetails")
	api.RegisterMessage((*FlowClassifyDump)(nil), "classify.FlowClassifyDump")
	api.RegisterMessage((*FlowClassifySetInterface)(nil), "classify.FlowClassifySetInterface")
	api.RegisterMessage((*FlowClassifySetInterfaceReply)(nil), "classify.FlowClassifySetInterfaceReply")
	api.RegisterMessage((*InputACLSetInterface)(nil), "classify.InputACLSetInterface")
	api.RegisterMessage((*InputACLSetInterfaceReply)(nil), "classify.InputACLSetInterfaceReply")
	api.RegisterMessage((*OutputACLSetInterface)(nil), "classify.OutputACLSetInterface")
	api.RegisterMessage((*OutputACLSetInterfaceReply)(nil), "classify.OutputACLSetInterfaceReply")
	api.RegisterMessage((*PolicerClassifyDetails)(nil), "classify.PolicerClassifyDetails")
	api.RegisterMessage((*PolicerClassifyDump)(nil), "classify.PolicerClassifyDump")
	api.RegisterMessage((*PolicerClassifySetInterface)(nil), "classify.PolicerClassifySetInterface")
	api.RegisterMessage((*PolicerClassifySetInterfaceReply)(nil), "classify.PolicerClassifySetInterfaceReply")
}

// Messages returns list of all messages in this module.
func AllMessages() []api.Message {
	return []api.Message{
		(*ClassifyAddDelSession)(nil),
		(*ClassifyAddDelSessionReply)(nil),
		(*ClassifyAddDelTable)(nil),
		(*ClassifyAddDelTableReply)(nil),
		(*ClassifySessionDetails)(nil),
		(*ClassifySessionDump)(nil),
		(*ClassifySetInterfaceIPTable)(nil),
		(*ClassifySetInterfaceIPTableReply)(nil),
		(*ClassifySetInterfaceL2Tables)(nil),
		(*ClassifySetInterfaceL2TablesReply)(nil),
		(*ClassifyTableByInterface)(nil),
		(*ClassifyTableByInterfaceReply)(nil),
		(*ClassifyTableIds)(nil),
		(*ClassifyTableIdsReply)(nil),
		(*ClassifyTableInfo)(nil),
		(*ClassifyTableInfoReply)(nil),
		(*FlowClassifyDetails)(nil),
		(*FlowClassifyDump)(nil),
		(*FlowClassifySetInterface)(nil),
		(*FlowClassifySetInterfaceReply)(nil),
		(*InputACLSetInterface)(nil),
		(*InputACLSetInterfaceReply)(nil),
		(*OutputACLSetInterface)(nil),
		(*OutputACLSetInterfaceReply)(nil),
		(*PolicerClassifyDetails)(nil),
		(*PolicerClassifyDump)(nil),
		(*PolicerClassifySetInterface)(nil),
		(*PolicerClassifySetInterfaceReply)(nil),
	}
}

// RPCService represents RPC service API for classify module.
type RPCService interface {
	DumpClassifySession(ctx context.Context, in *ClassifySessionDump) (RPCService_DumpClassifySessionClient, error)
	DumpFlowClassify(ctx context.Context, in *FlowClassifyDump) (RPCService_DumpFlowClassifyClient, error)
	DumpPolicerClassify(ctx context.Context, in *PolicerClassifyDump) (RPCService_DumpPolicerClassifyClient, error)
	ClassifyAddDelSession(ctx context.Context, in *ClassifyAddDelSession) (*ClassifyAddDelSessionReply, error)
	ClassifyAddDelTable(ctx context.Context, in *ClassifyAddDelTable) (*ClassifyAddDelTableReply, error)
	ClassifySetInterfaceIPTable(ctx context.Context, in *ClassifySetInterfaceIPTable) (*ClassifySetInterfaceIPTableReply, error)
	ClassifySetInterfaceL2Tables(ctx context.Context, in *ClassifySetInterfaceL2Tables) (*ClassifySetInterfaceL2TablesReply, error)
	ClassifyTableByInterface(ctx context.Context, in *ClassifyTableByInterface) (*ClassifyTableByInterfaceReply, error)
	ClassifyTableIds(ctx context.Context, in *ClassifyTableIds) (*ClassifyTableIdsReply, error)
	ClassifyTableInfo(ctx context.Context, in *ClassifyTableInfo) (*ClassifyTableInfoReply, error)
	FlowClassifySetInterface(ctx context.Context, in *FlowClassifySetInterface) (*FlowClassifySetInterfaceReply, error)
	InputACLSetInterface(ctx context.Context, in *InputACLSetInterface) (*InputACLSetInterfaceReply, error)
	OutputACLSetInterface(ctx context.Context, in *OutputACLSetInterface) (*OutputACLSetInterfaceReply, error)
	PolicerClassifySetInterface(ctx context.Context, in *PolicerClassifySetInterface) (*PolicerClassifySetInterfaceReply, error)
}

type serviceClient struct {
	ch api.Channel
}

func NewServiceClient(ch api.Channel) RPCService {
	return &serviceClient{ch}
}

func (c *serviceClient) DumpClassifySession(ctx context.Context, in *ClassifySessionDump) (RPCService_DumpClassifySessionClient, error) {
	stream := c.ch.SendMultiRequest(in)
	x := &serviceClient_DumpClassifySessionClient{stream}
	return x, nil
}

type RPCService_DumpClassifySessionClient interface {
	Recv() (*ClassifySessionDetails, error)
}

type serviceClient_DumpClassifySessionClient struct {
	api.MultiRequestCtx
}

func (c *serviceClient_DumpClassifySessionClient) Recv() (*ClassifySessionDetails, error) {
	m := new(ClassifySessionDetails)
	stop, err := c.MultiRequestCtx.ReceiveReply(m)
	if err != nil {
		return nil, err
	}
	if stop {
		return nil, io.EOF
	}
	return m, nil
}

func (c *serviceClient) DumpFlowClassify(ctx context.Context, in *FlowClassifyDump) (RPCService_DumpFlowClassifyClient, error) {
	stream := c.ch.SendMultiRequest(in)
	x := &serviceClient_DumpFlowClassifyClient{stream}
	return x, nil
}

type RPCService_DumpFlowClassifyClient interface {
	Recv() (*FlowClassifyDetails, error)
}

type serviceClient_DumpFlowClassifyClient struct {
	api.MultiRequestCtx
}

func (c *serviceClient_DumpFlowClassifyClient) Recv() (*FlowClassifyDetails, error) {
	m := new(FlowClassifyDetails)
	stop, err := c.MultiRequestCtx.ReceiveReply(m)
	if err != nil {
		return nil, err
	}
	if stop {
		return nil, io.EOF
	}
	return m, nil
}

func (c *serviceClient) DumpPolicerClassify(ctx context.Context, in *PolicerClassifyDump) (RPCService_DumpPolicerClassifyClient, error) {
	stream := c.ch.SendMultiRequest(in)
	x := &serviceClient_DumpPolicerClassifyClient{stream}
	return x, nil
}

type RPCService_DumpPolicerClassifyClient interface {
	Recv() (*PolicerClassifyDetails, error)
}

type serviceClient_DumpPolicerClassifyClient struct {
	api.MultiRequestCtx
}

func (c *serviceClient_DumpPolicerClassifyClient) Recv() (*PolicerClassifyDetails, error) {
	m := new(PolicerClassifyDetails)
	stop, err := c.MultiRequestCtx.ReceiveReply(m)
	if err != nil {
		return nil, err
	}
	if stop {
		return nil, io.EOF
	}
	return m, nil
}

func (c *serviceClient) ClassifyAddDelSession(ctx context.Context, in *ClassifyAddDelSession) (*ClassifyAddDelSessionReply, error) {
	out := new(ClassifyAddDelSessionReply)
	err := c.ch.SendRequest(in).ReceiveReply(out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serviceClient) ClassifyAddDelTable(ctx context.Context, in *ClassifyAddDelTable) (*ClassifyAddDelTableReply, error) {
	out := new(ClassifyAddDelTableReply)
	err := c.ch.SendRequest(in).ReceiveReply(out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serviceClient) ClassifySetInterfaceIPTable(ctx context.Context, in *ClassifySetInterfaceIPTable) (*ClassifySetInterfaceIPTableReply, error) {
	out := new(ClassifySetInterfaceIPTableReply)
	err := c.ch.SendRequest(in).ReceiveReply(out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serviceClient) ClassifySetInterfaceL2Tables(ctx context.Context, in *ClassifySetInterfaceL2Tables) (*ClassifySetInterfaceL2TablesReply, error) {
	out := new(ClassifySetInterfaceL2TablesReply)
	err := c.ch.SendRequest(in).ReceiveReply(out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serviceClient) ClassifyTableByInterface(ctx context.Context, in *ClassifyTableByInterface) (*ClassifyTableByInterfaceReply, error) {
	out := new(ClassifyTableByInterfaceReply)
	err := c.ch.SendRequest(in).ReceiveReply(out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serviceClient) ClassifyTableIds(ctx context.Context, in *ClassifyTableIds) (*ClassifyTableIdsReply, error) {
	out := new(ClassifyTableIdsReply)
	err := c.ch.SendRequest(in).ReceiveReply(out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serviceClient) ClassifyTableInfo(ctx context.Context, in *ClassifyTableInfo) (*ClassifyTableInfoReply, error) {
	out := new(ClassifyTableInfoReply)
	err := c.ch.SendRequest(in).ReceiveReply(out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serviceClient) FlowClassifySetInterface(ctx context.Context, in *FlowClassifySetInterface) (*FlowClassifySetInterfaceReply, error) {
	out := new(FlowClassifySetInterfaceReply)
	err := c.ch.SendRequest(in).ReceiveReply(out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serviceClient) InputACLSetInterface(ctx context.Context, in *InputACLSetInterface) (*InputACLSetInterfaceReply, error) {
	out := new(InputACLSetInterfaceReply)
	err := c.ch.SendRequest(in).ReceiveReply(out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serviceClient) OutputACLSetInterface(ctx context.Context, in *OutputACLSetInterface) (*OutputACLSetInterfaceReply, error) {
	out := new(OutputACLSetInterfaceReply)
	err := c.ch.SendRequest(in).ReceiveReply(out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serviceClient) PolicerClassifySetInterface(ctx context.Context, in *PolicerClassifySetInterface) (*PolicerClassifySetInterfaceReply, error) {
	out := new(PolicerClassifySetInterfaceReply)
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
