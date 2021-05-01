-- Decoder for JT808 is from https://github.com/worker24h/jt808-lua-wireshark, with added support for tcp reassemble and code factoring.

local bit32 = require "bit32"

JT808_proto = Proto("jt808", "JT808 Protocol")
JT808_proto.fields = {}
local jt808_fields = JT808_proto.fields

jt808_fields.flag = ProtoField.uint8("jt808.flag", "Flag", base.HEX)
local msg_type = {
    [0x0001] = "[终端通用应答]",
    [0x8001] = "[平台通用应答]",
    [0x0002] = "[终端心跳]",
    [0x8003] = "[服务器补传分包请求]",
    [0x0005] = "[终端补传分包请求]",
    [0x0100] = "[终端注册]",
    [0x8100] = "[终端注册应答]",
    [0x0003] = "[终端注销]",
    [0x0004] = "[查询服务器时间]",
    [0x0102] = "[终端鉴权]",
    [0x8103] = "[设置终端参数]",
    [0x8104] = "[查询终端参数]",
    [0x0104] = "[查询终端参数应答]",
    [0x8105] = "[终端控制]",
    [0x8106] = "[查询指定终端参数]",
    [0x8107] = "[查询终端属性]",
    [0x0107] = "[查询终端属性应答]",
    [0x8108] = "[下发终端升级包]",
    [0x0108] = "[终端升级结果通知]",
    [0x0200] = "[位置信息汇报]",
    [0x8201] = "[位置信息查询]",
    [0x0201] = "[位置信息查询应答]",
    [0x8202] = "[临时位置跟踪控制]",
    [0x8301] = "[事件设置]",
    [0x0301] = "[事件报告]",
    [0x8302] = "[提问下发]",
    [0x0302] = "[提问应答]",
    [0x8303] = "[信息点播菜单设置]",
    [0x0303] = "[信息点播/取消]",
    [0x8304] = "[信息服务]",
    [0x8004] = "[查询服务器时间应答]",
    [0x8400] = "[电话回拨]",
    [0x8401] = "[设置电话本]",
    [0x8500] = "[车辆控制]",
    [0x0500] = "[车辆控制应答]",
    [0x8600] = "[设置圆形区域]",
    [0x8601] = "[删除圆形区域]",
    [0x8602] = "[设置矩形区域]",
    [0x8603] = "[删除矩形区域]",
    [0x8604] = "[设置多边形区域]",
    [0x8605] = "[删除多边形区域]",
    [0x8606] = "[设置路线]",
    [0x8607] = "[删除路线]",
    [0x8700] = "[行驶记录仪数据采集命令]",
    [0x0700] = "[行驶记录仪数据上传]",
    [0x8203] = "[人工确认报警消息]",
    [0x8204] = "[服务器向终端发起链路检测请求]",
    [0x8300] = "[文本信息下发]",
    [0x0702] = "[驾驶员身份信息采集上报]",
    [0x8702] = "[上报驾驶员身份信息请求]",
    [0x0704] = "[定位数据批量上传]",
    [0x0705] = "[CAN 总线数据上传]",
    [0x0800] = "[多媒体事件信息上传]",
    [0x0801] = "[多媒体数据上传]",
    [0x8800] = "[多媒体数据上传应答]",
    [0x8801] = "[摄像头立即拍摄命令]",
    [0x0805] = "[摄像头立即拍摄命令应答]",
    [0x8802] = "[存储多媒体数据检索]",
    [0x0802] = "[存储多媒体数据检索应答]",
    [0x8608] = "[查询区域或线路数据]",
    [0x0608] = "[查询区域或线路数据应答]",
    [0x8701] = "[行驶记录仪参数下传命令]",
    [0x0701] = "[电子运单上报]",
    [0x8803] = "[存储多媒体数据上传]",
    [0x8804] = "[录音开始命令]",
    [0x8805] = "[单条存储多媒体数据检索上传命令]",
    [0x8900] = "[数据下行透传]",
    [0x0900] = "[数据上行透传]",
    [0x0901] = "[数据压缩上报]",
    [0x8A00] = "[平台 RSA 公钥]",
    [0x0A00] = "[终端 RSA 公钥]",
    -- Extended in JT/T 1708
    [0x9003] = "[1708查询终端音视频属性]",
    [0x1003] = "[1708终端上传音视频属性]",
    [0x1005] = "[1708终端上传乘客流量]",
    [0x9101] = "[1708实时音视频传输请求]",
    [0x9102] = "[1708音视频实时传输控制]",
    [0x9105] = "[1708实时音视频传输状态通知]",
    [0x9205] = "[1708查询资源列表]",
    [0x1205] = "[1708终端上传音视频资源列表]",
    [0x9201] = "[1708平台下发远程录像回放请求]",
    [0x9202] = "[1708平台下发远程录像回放控制]",
    [0x9206] = "[1708文件上传指令]",
    [0x1206] = "[1708文件上传完成通知]",
    [0x9207] = "[1708文件上传控制]",
    [0x9301] = "[1708云台旋转]",
    [0x9302] = "[1708云台调整焦距控制]",
    [0x9303] = "[1708云台调整光圈控制]",
    [0x9304] = "[1708云台雨刷控制]",
    [0x9305] = "[1708红外补光控制]",
    [0x9306] = "[1708云台变倍控制]",
}

jt808_fields.msg_type = ProtoField.uint16("jt808.msg_type", "Msg Type", base.HEX, msg_type)
jt808_fields.msg_attr = ProtoField.uint16("jt808.msg_attr", "Msg Attr", base.HEX)
jt808_fields.msg_attr_resv   = ProtoField.uint16("jt808.msg_attr.reserve", "Reserve", base.HEX, nil, 0x8000)
local msg_attr_version = {
    [0] = "无版本标识(2011)",
    [1] = "有版本标识(2019+)"
}
jt808_fields.msg_attr_version_flag   = ProtoField.uint16("jt808.msg_attr.version_flag", "Version", base.HEX, msg_attr_version, 0x4000)
jt808_fields.msg_attr_flag   = ProtoField.uint16("jt808.msg_attr.flag", "Flag", base.HEX, nil, 0x2000)
jt808_fields.msg_attr_secure = ProtoField.uint16("jt808.msg_attr.secure", "Secure", base.HEX, nil, 0x1C00)
jt808_fields.msg_attr_length = ProtoField.uint16("jt808.msg_attr.length", "Length", base.HEX, nil, 0x03FF)
jt808_fields.protocol_version = ProtoField.uint8("jt808.protocol_version", "Protocol Version", base.DEC)
jt808_fields.terminal_phone_number = ProtoField.string("jt808.terminal_phone_number", "Terminal Phone Number")
jt808_fields.msg_seq_no = ProtoField.uint16("jt808.seq", "Msg Sequence No", base.DEC)
jt808_fields.sub_pkg_cnt = ProtoField.uint16("jt808.sub_pkg_cnt", "Subpackage Cnt", base.DEC)
jt808_fields.sub_pkg_idx = ProtoField.uint16("jt808.sub_pkg_idx", "Subpackage Idx", base.DEC)
jt808_fields.crc = ProtoField.uint8("jt808.crc", "CRC", base.HEX)

jt808_fields.unknown_fields = ProtoField.bytes("jt808_fields.unknown_fields", "Unknown Fields")
-- Export info.
local found_unknown_fields = ProtoExpert.new("jt808_fields.expert.unknown_fields", "Found Unknown Fields", expert.group.MALFORMED, expert.severity.WARN)
local no_body_handler = ProtoExpert.new("jt808_fields.expert.no_body_handler", "No body handler", expert.group.PROTOCOL, expert.severity.WARN)
JT808_proto.experts = { found_unknown_fields, no_body_handler }

-- Mininal buf length that we can determine msg_len.
local JT808_MSG_LEN_POS_LEN = 5

-------------------------------parse function-------------------------------------------------

local function get_one_byte(buffer, offset)
    return buffer(offset, 1):uint(), 1
end

local function get_two_bytes(buffer, offset)
    return buffer(offset, 2):uint(), 2
end

local function get_four_bytes(buffer, offset)
    return buffer(offset, 4):uint(), 4
end

local function get_bcd_string(buffer, offset, len)
    return buffer(offset, len):string(ENC_BCD_DIGITS_0_9), len
end

local function get_gbk_string(buffer, offset, len)
    return buffer(offset, len):string(ENC_GB18030), len
end

jt808_fields.location_time = ProtoField.bytes("jt808.location_date", "Date")

local function parse_time(tvbuf, offset, subtree)
    local time_bytes = tvbuf(offset, 6):bytes()
    subtree:add(jt808_fields.location_time, tvbuf(offset, 6), string.format("20%02x-%02x-%02x %02x:%02x:%02x", time_bytes[0], time_bytes[1], time_bytes[2], time_bytes[3], time_bytes[4], time_bytes[5]))
    return offset + 6
end

---------------------------- Sub message handlers ----------------------------
local msg_type_handler = {}

---------------------------- 终端通用应答[0x0001] ----------------------------

jt808_fields.terminal_ack_seq_no = ProtoField.uint16("jt808.terminal_ack_seq_no", "Ack Sequence No", base.DEC)
jt808_fields.terminal_ack_msg_type = ProtoField.uint16("jt808.terminal_ack_msg_type", "Ack Message Type", base.DEC)
local terminal_common_result = {
    [0x0] = "[成功/确认]",
    [0x1] = "[失败]",
    [0x2] = "[消息有误]",
    [0x3] = "[不支持]",
}
jt808_fields.terminal_common_result = ProtoField.uint8("jt808.terminal_common_result", "Common Result", base.HEX, terminal_common_result)

local function dissect_terminal_common_response_0001(tvbuf, offset, subtree, end_offset, protocol_version)
    subtree:add(jt808_fields.terminal_ack_seq_no, tvbuf(offset, 2))
    offset = offset + 2

    subtree:add(jt808_fields.terminal_ack_msg_type, tvbuf(offset, 2))
    offset = offset + 2

    subtree:add(jt808_fields.terminal_common_result, tvbuf(offset, 1))
    offset = offset + 1

    -- Check for unknown fields.
    if end_offset > offset then
        subtree:add(jt808_fields.unknown_fields, tvbuf(offset, end_offset-offset))
        subtree:add_proto_expert_info(found_unknown_fields)
        offset = end_offset
    end

    return offset
end
msg_type_handler[0x0001] = dissect_terminal_common_response_0001

---------------------------- 平台通用应答[0x8001] ----------------------------

jt808_fields.platform_ack_seq_no = ProtoField.uint16("jt808.platform_ack_seq_no", "Ack Sequence No", base.DEC)
jt808_fields.platform_ack_msg_type = ProtoField.uint16("jt808.platform_ack_msg_type", "Ack Message Type", base.DEC)
local platform_common_result = {
    [0x0] = "[成功/确认]",
    [0x1] = "[失败]",
    [0x2] = "[消息有误]",
    [0x3] = "[不支持]",
    [0x4] = "[报警处理确认]"
}
jt808_fields.platform_common_result = ProtoField.uint8("jt808.platform_common_result", "Common Result", base.HEX, platform_common_result)

local function dissect_platform_common_response_8001(tvbuf, offset, subtree, end_offset, protocol_version)
    subtree:add(jt808_fields.platform_ack_seq_no, tvbuf(offset, 2))
    offset = offset + 2

    subtree:add(jt808_fields.platform_ack_msg_type, tvbuf(offset, 2))
    offset = offset + 2

    subtree:add(jt808_fields.platform_common_result, tvbuf(offset, 1))
    offset = offset + 1

    -- Check for unknown fields.
    if end_offset > offset then
        subtree:add(jt808_fields.unknown_fields, tvbuf(offset, end_offset-offset))
        subtree:add_proto_expert_info(found_unknown_fields)
        offset = end_offset
    end

    return offset
end
msg_type_handler[0x8001] = dissect_platform_common_response_8001

---------------------------- 查询服务器时间应答[0x8004] ----------------------------

local function dissect_query_server_time_response_8004(tvbuf, offset, subtree, end_offset, protocol_version)
    offset = parse_time(tvbuf, offset, subtree)

    -- Check for unknown fields.
    if end_offset > offset then
        subtree:add(jt808_fields.unknown_fields, tvbuf(offset, end_offset-offset))
        subtree:add_proto_expert_info(found_unknown_fields)
        offset = end_offset
    end

    return offset
end
msg_type_handler[0x8004] = dissect_query_server_time_response_8004

---------------------------- 终端注册[0x0100] ----------------------------

local province_id = {
    [11] = "[北京]",
    [12] = "[天津]",
    [13] = "[河北]",
    [14] = "[山西]",
    [15] = "[内蒙古]",
    [21] = "[辽宁]",
    [22] = "[吉林]",
    [23] = "[黑龙江]",
    [31] = "[上海]",
    [32] = "[江苏]",
    [33] = "[浙江]",
    [34] = "[安徽]",
    [35] = "[福建]",
    [36] = "[江西]",
    [37] = "[山东]",
    [41] = "[河南]",
    [42] = "[湖北]",
    [43] = "[湖南]",
    [44] = "[广东]",
    [45] = "[广西]",
    [46] = "[海南]",
    [50] = "[重庆]",
    [51] = "[四川]",
    [52] = "[贵州]",
    [53] = "[云南]",
    [54] = "[西藏]",
    [61] = "[陕西]",
    [62] = "[甘肃]",
    [63] = "[青海]",
    [64] = "[宁夏]",
    [65] = "[新疆]",
    [71] = "[台湾]",
    [81] = "[香港]",
    [82] = "[澳门]",
}
jt808_fields.terminal_reg_province_id = ProtoField.uint16("jt808.terminal_reg_province_id", "Province ID", base.DEC, province_id)
-- The GB2260 city table is too large.
jt808_fields.terminal_reg_city_id = ProtoField.uint16("jt808.terminal_reg_city_id", "City ID", base.DEC)
jt808_fields.terminal_reg_vendor = ProtoField.bytes("jt808.terminal_reg_vendor", "Vendor Info")
jt808_fields.terminal_reg_terminal_model = ProtoField.string("jt808.terminal_reg_terminal_model", "Terminal Model")
jt808_fields.terminal_reg_terminal_id = ProtoField.string("jt808.terminal_reg_terminal_id", "Terminal Id")
-- 车牌颜色
local plate_color = {
  [0] = "[未知]",
  [1] = "[蓝色]",
  [2] = "[黄色]",
  [3] = "[黑色]",
  [4] = "[白色]",
  [9] = "[其他]",
}
jt808_fields.terminal_reg_terminal_plate_color = ProtoField.uint8("jt808.terminal_reg_terminal_plate_color", "Plate Color", base.HEX, plate_color)
jt808_fields.terminal_reg_terminal_plate_number = ProtoField.string("jt808.terminal_reg_terminal_plate_number", "Plate Number")

local function dissect_terminal_register_0100(tvbuf, offset, subtree, end_offset, version, protocol_version)
    subtree:add(jt808_fields.terminal_reg_province_id, tvbuf(offset, 2))
    offset = offset + 2

    subtree:add(jt808_fields.terminal_reg_city_id, tvbuf(offset, 2))
    offset = offset + 2

    local vendor_len = 5
    if protocol_version == 1 then
        vendor_len = 11
    end

    subtree:add(jt808_fields.terminal_reg_vendor, tvbuf(offset, vendor_len))
    offset = offset + vendor_len

    local model_len = 8
    if protocol_version == 1 then
        model_len = 30
    end
    subtree:add(jt808_fields.terminal_reg_terminal_model, tvbuf(offset, model_len))
    offset = offset + model_len

    local id_len = 7
    if protocol_version == 1 then
        id_len = 30
    end
    subtree:add(jt808_fields.terminal_reg_terminal_id, tvbuf(offset, id_len))
    offset = offset + id_len

    subtree:add(jt808_fields.terminal_reg_terminal_plate_color, tvbuf(offset, 1))
    offset = offset + 1

    local plate_number_len = end_offset - offset
    local plate_number = get_gbk_string(tvbuf, offset, plate_number_len)
    subtree:add(jt808_fields.terminal_reg_terminal_plate_number, tvbuf(offset, plate_number_len), plate_number)
    offset = offset + plate_number_len

    -- Check for unknown fields.
    if end_offset > offset then
        subtree:add(jt808_fields.unknown_fields, tvbuf(offset, end_offset-offset))
        subtree:add_proto_expert_info(found_unknown_fields)
        offset = end_offset
    end

    return offset
end
msg_type_handler[0x0100] = dissect_terminal_register_0100

---------------------------- 终端注册应答 ----------------------------

jt808_fields.terminal_reg_response_ack_seq_no = ProtoField.uint16("jt808.terminal_reg_response_ack_seq_no", "Ack Sequence No", base.DEC)
local reg_result = {
  [0] = "[成功]",
  [1] = "[车辆已被注册]",
  [2] = "[数据库中无该车辆]",
  [3] = "[终端已经被注册]",
  [4] = "[数据库中无该终端]",
}
jt808_fields.terminal_reg_response_result = ProtoField.uint8("jt808.terminal_reg_response_result", "Result", base.HEX, reg_result)
jt808_fields.terminal_reg_response_authcode = ProtoField.string("jt808.terminal_reg_response_authcode", "Response AuthCode")

local function dissect_terminal_register_8100(tvbuf, offset, subtree, end_offset)
    subtree:add(jt808_fields.terminal_reg_response_ack_seq_no, tvbuf(offset, 2))
    offset = offset + 2

    subtree:add(jt808_fields.terminal_reg_response_result, tvbuf(offset, 1))
    offset = offset + 1

    local authcode_len = end_offset - offset
    subtree:add(jt808_fields.terminal_reg_response_authcode, tvbuf(offset, authcode_len))
    offset = offset + authcode_len

    -- Check for unknown fields.
    if end_offset > offset then
        subtree:add(jt808_fields.unknown_fields, tvbuf(offset, end_offset-offset))
        subtree:add_proto_expert_info(found_unknown_fields)
        offset = end_offset
    end

    return offset
end
msg_type_handler[0x8100] = dissect_terminal_register_8100

---------------------------- 终端鉴权 ----------------------------

jt808_fields.terminal_authcode = ProtoField.string("jt808.terminal_authcode", "Terminal AuthCode")
jt808_fields.terminal_imei = ProtoField.string("jt808.terminal_imei", "Terminal IMEI")
jt808_fields.terminal_software_version = ProtoField.string("jt808.terminal_software_version", "Terminal Software Version")

local function dissect_terminal_authcode_0102(tvbuf, offset, subtree, end_offset, protocol_version)

    local authcode_len = end_offset - offset
    if protocol_version == 1 then
        authcode_len, _ = get_one_byte(tvbuf, offset)
        offset = offset + 1
    end
    
    subtree:add(jt808_fields.terminal_authcode, tvbuf(offset, authcode_len))
    offset = offset + authcode_len

    if protocol_version == 1 then
        -- Load IMEI
        subtree:add(jt808_fields.terminal_imei, tvbuf(offset, 15))
        offset = offset + 15
        -- Load software version
        subtree:add(jt808_fields.terminal_software_version, tvbuf(offset, 20))
        offset = offset + 20
    end

    -- Check for unknown fields.
    if end_offset > offset then
        subtree:add(jt808_fields.unknown_fields, tvbuf(offset, end_offset-offset))
        subtree:add_proto_expert_info(found_unknown_fields)
        offset = end_offset
    end

    return offset
end
msg_type_handler[0x0102] = dissect_terminal_authcode_0102


---------------------------- 位置信息汇报 ----------------------------


jt808_fields.location_basic_warning = ProtoField.uint32("jt808.location_basic_warning", "Warning", base.HEX)
local warnging0 = {
  [0] = "",
  [1] = "[紧急报警]"
}
jt808_fields.location_basic_warning0 = ProtoField.uint32("jt808.location_basic_warning0", "Warning", base.HEX, warnging0, 0x80000000)

local warnging1 = {
  [0] = "",
  [1] = "[超速报警]"
}
jt808_fields.location_basic_warning1 = ProtoField.uint32("jt808.location_basic_warning1", "Warning", base.HEX, warnging1, 0x40000000)

local warnging2 = {
  [0] = "",
  [1] = "[疲劳驾驶报警]"
}
jt808_fields.location_basic_warning2 = ProtoField.uint32("jt808.location_basic_warning2", "Warning", base.HEX, warnging2, 0x20000000)

local warnging3 = {
  [0] = "",
  [1] = "[危险驾驶行为报警]"
}
jt808_fields.location_basic_warning3 = ProtoField.uint32("jt808.location_basic_warning3", "Warning", base.HEX, warnging3, 0x10000000)

local warnging4 = {
  [0] = "",
  [1] = "[GNSS模块发生故障报警]"
}
jt808_fields.location_basic_warning4 = ProtoField.uint32("jt808.location_basic_warning4", "Warning", base.HEX, warnging4, 0x08000000)

local warnging5 = {
  [0] = "",
  [1] = "[GNSS天线未接或被剪断报警]"
}
jt808_fields.location_basic_warning5 = ProtoField.uint32("jt808.location_basic_warning5", "Warning", base.HEX, warnging5, 0x04000000)

local warnging6 = {
  [0] = "",
  [1] = "[GNSS天线短路报警]"
}
jt808_fields.location_basic_warning6 = ProtoField.uint32("jt808.location_basic_warning6", "Warning", base.HEX, warnging6, 0x02000000)

local warnging7 = {
  [0] = "",
  [1] = "[终端主电源欠压报警]"
}
jt808_fields.location_basic_warning7 = ProtoField.uint32("jt808.location_basic_warning7", "Warning", base.HEX, warnging7, 0x01000000)

local warnging8 = {
  [0] = "",
  [1] = "[终端主电源掉电报警]"
}
jt808_fields.location_basic_warning8 = ProtoField.uint32("jt808.location_basic_warning8", "Warning", base.HEX, warnging8, 0x00800000)

local warnging9 = {
  [0] = "",
  [1] = "[终端LCD或显示器故障报警]"
}
jt808_fields.location_basic_warning9 = ProtoField.uint32("jt808.location_basic_warning9", "Warning", base.HEX, warnging9, 0x00400000)

local warnging10 = {
  [0] = "",
  [1] = "[TTS模块故障报警]"
}
jt808_fields.location_basic_warning10 = ProtoField.uint32("jt808.location_basic_warning10", "Warning", base.HEX, warnging10, 0x00200000)

local warnging11 = {
  [0] = "",
  [1] = "[摄像头故障报警]"
}
jt808_fields.location_basic_warning11 = ProtoField.uint32("jt808.location_basic_warning11", "Warning", base.HEX, warnging11, 0x00100000)

local warnging12 = {
  [0] = "",
  [1] = "[道路运输证IC卡模块故障报警]"
}
jt808_fields.location_basic_warning12 = ProtoField.uint32("jt808.location_basic_warning12", "Warning", base.HEX, warnging12, 0x00080000)

local warnging13 = {
  [0] = "",
  [1] = "[超速预警]"
}
jt808_fields.location_basic_warning13 = ProtoField.uint32("jt808.location_basic_warning13", "Warning", base.HEX, warnging13, 0x00040000)

local warnging14 = {
  [0] = "",
  [1] = "[疲劳驾驶预警]"
}
jt808_fields.location_basic_warning14 = ProtoField.uint32("jt808.location_basic_warning14", "Warning", base.HEX, warnging14, 0x00020000)

local warnging15 = {
  [0] = "",
  [1] = "[违规行驶报警]"
}
jt808_fields.location_basic_warning15 = ProtoField.uint32("jt808.location_basic_warning15", "Warning", base.HEX, warnging15, 0x00010000)

local warnging16 = {
  [0] = "",
  [1] = "[胎压预警]"
}
jt808_fields.location_basic_warning16 = ProtoField.uint32("jt808.location_basic_warning16", "Warning", base.HEX, warnging16, 0x00008000)

local warnging17 = {
  [0] = "",
  [1] = "[右转盲区异常报警]"
}
jt808_fields.location_basic_warning17 = ProtoField.uint32("jt808.location_basic_warning17", "Warning", base.HEX, warnging17, 0x00004000)

local warnging18 = {
  [0] = "",
  [1] = "[当天累计驾驶超时报警]"
}
jt808_fields.location_basic_warning18 = ProtoField.uint32("jt808.location_basic_warning18", "Warning", base.HEX, warnging18, 0x00002000)

local warnging19 = {
  [0] = "",
  [1] = "[超时停车报警]"
}
jt808_fields.location_basic_warning19 = ProtoField.uint32("jt808.location_basic_warning19", "Warning", base.HEX, warnging19, 0x00001000)

local warnging20 = {
  [0] = "",
  [1] = "[进出区域报警]"
}
jt808_fields.location_basic_warning20 = ProtoField.uint32("jt808.location_basic_warning20", "Warning", base.HEX, warnging20, 0x00000800)
local warnging21 = {
  [0] = "",
  [1] = "[进出路线报警]"
}
jt808_fields.location_basic_warning21 = ProtoField.uint32("jt808.location_basic_warning21", "Warning", base.HEX, warnging21, 0x00000400)
local warnging22 = {
  [0] = "",
  [1] = "[路段行驶时间不足/过长报警]"
}
jt808_fields.location_basic_warning22 = ProtoField.uint32("jt808.location_basic_warning22", "Warning", base.HEX, warnging22, 0x00000200)
local warnging23 = {
  [0] = "",
  [1] = "[路线偏离报警]"
}
jt808_fields.location_basic_warning23 = ProtoField.uint32("jt808.location_basic_warning23", "Warning", base.HEX, warnging23, 0x00000100)
local warnging24 = {
  [0] = "",
  [1] = "[车辆VSS故障]"
}
jt808_fields.location_basic_warning24 = ProtoField.uint32("jt808.location_basic_warning24", "Warning", base.HEX, warnging24, 0x00000080)
local warnging25 = {
  [0] = "",
  [1] = "[车辆油量异常报警]"
}
jt808_fields.location_basic_warning25 = ProtoField.uint32("jt808.location_basic_warning25", "Warning", base.HEX, warnging25, 0x00000040)
local warnging26 = {
  [0] = "",
  [1] = "[车联被盗报警]"
}
jt808_fields.location_basic_warning26 = ProtoField.uint32("jt808.location_basic_warning26", "Warning", base.HEX, warnging26, 0x00000020)
local warnging27 = {
  [0] = "",
  [1] = "[车辆非法点火报警]"
}
jt808_fields.location_basic_warning27 = ProtoField.uint32("jt808.location_basic_warning27", "Warning", base.HEX, warnging27, 0x00000010)
local warnging28 = {
  [0] = "",
  [1] = "[车辆非法位移报警]"
}
jt808_fields.location_basic_warning28 = ProtoField.uint32("jt808.location_basic_warning28", "Warning", base.HEX, warnging28, 0x00000008)
local warnging29 = {
  [0] = "",
  [1] = "[碰撞侧翻报警]"
}
jt808_fields.location_basic_warning29 = ProtoField.uint32("jt808.location_basic_warning29", "Warning", base.HEX, warnging29, 0x00000004)
local warnging30 = {
  [0] = "",
  [1] = "[侧翻预警]"
}
jt808_fields.location_basic_warning30 = ProtoField.uint32("jt808.location_basic_warning30", "Warning", base.HEX, warnging30, 0x00000002)
local warnging31 = {
  [0] = "[Resv]",
  [1] = "[Resv]"
}
jt808_fields.location_basic_warning31 = ProtoField.uint32("jt808.location_basic_warning31", "Warning", base.HEX, warnging31, 0x00000001)
jt808_fields.location_basic_status = ProtoField.uint32("jt808.location_basic_status", "Status", base.HEX)

local status0 = {
  [0] = "[ACC关闭]",
  [1] = "[ACC开启]"
}
jt808_fields.location_basic_status0 = ProtoField.uint32("jt808.location_basic_status0", "Acc", base.HEX, status0, 0x80000000)

local status1 = {
  [0] = "[未定位]",
  [1] = "[定位]"
}
jt808_fields.location_basic_status1 = ProtoField.uint32("jt808.location_basic_status1", "Location", base.HEX, status1, 0x40000000)

local status2 = {
  [0] = "[北纬]",
  [1] = "[南纬]"
}
jt808_fields.location_basic_status2 = ProtoField.uint32("jt808.location_basic_status2", "Latitude", base.HEX, status2, 0x20000000)

local status3 = {
  [0] = "[东经]",
  [1] = "[西经]"
}
jt808_fields.location_basic_status3 = ProtoField.uint32("jt808.location_basic_status3", "Longitude", base.HEX, status3, 0x10000000)

local status4 = {
  [0] = "[运营]",
  [1] = "[未运营]"
}
jt808_fields.location_basic_status4 = ProtoField.uint32("jt808.location_basic_status4", "Operating", base.HEX, status4, 0x08000000)

local status5 = {
  [0] = "[经纬度未加密]",
  [1] = "[经纬度加密]"
}
jt808_fields.location_basic_status5 = ProtoField.uint32("jt808.location_basic_status5", "Encrypted", base.HEX, status5, 0x04000000)

local status6 = {
  [0] = "",
  [1] = "[紧急刹车系统采集的前撞预警]"
}
jt808_fields.location_basic_status6 = ProtoField.uint32("jt808.location_basic_status6", "Status", base.HEX, status6, 0x02000000)

local status7 = {
  [0] = "",
  [1] = "[车道偏移预警]"
}
jt808_fields.location_basic_status7 = ProtoField.uint32("jt808.location_basic_status7", "Status", base.HEX, status7, 0x01000000)

local status8_9 = {
  [00] = "[空车]",
  [01] = "[半载]",
  [10] = "[Resv]",
  [11] = "[满载]"
}
jt808_fields.location_basic_status8_9 = ProtoField.uint32("jt808.location_basic_status8_9", "Reserve", base.HEX, status8_9, 0x00C00000)

local status10 = {
  [0] = "[车辆油路正常]",
  [1] = "[车辆油路断开]"
}
jt808_fields.location_basic_status10 = ProtoField.uint32("jt808.location_basic_status10", "Oil", base.HEX, status10, 0x00200000)

local status11 = {
  [0] = "[车辆电路正常]",
  [1] = "[车辆电路断开]"
}
jt808_fields.location_basic_status11 = ProtoField.uint32("jt808.location_basic_status11", "Circuit", base.HEX, status11, 0x00100000)

local status12 = {
  [0] = "[车门解锁]",
  [1] = "[车门加锁]"
}
jt808_fields.location_basic_status12 = ProtoField.uint32("jt808.location_basic_status12", "DoorLock", base.HEX, status12, 0x00080000)

local status13 = {
  [0] = "[门1关]",
  [1] = "[门1开]"
}
jt808_fields.location_basic_status13 = ProtoField.uint32("jt808.location_basic_status13", "Door1", base.HEX, status13, 0x00040000)

local status14 = {
  [0] = "[门2关]",
  [1] = "[门2开]"
}
jt808_fields.location_basic_status14 = ProtoField.uint32("jt808.location_basic_status14", "Door2", base.HEX, status14, 0x00020000)

local status15 = {
  [0] = "[门3关]",
  [1] = "[门3开]"
}
jt808_fields.location_basic_status15 = ProtoField.uint32("jt808.location_basic_status15", "Door3", base.HEX, status15, 0x00010000)

local status16 = {
  [0] = "[门4关]",
  [1] = "[门4开]"
}
jt808_fields.location_basic_status16 = ProtoField.uint32("jt808.location_basic_status16", "Door4", base.HEX, status16, 0x00008000)

local status17 = {
  [0] = "[门5关]",
  [1] = "[门5开]"
}
jt808_fields.location_basic_status17 = ProtoField.uint32("jt808.location_basic_status17", "Door5", base.HEX, status17, 0x00004000)

local status18 = {
  [0] = "[未使用GPS卫星进行定位]",
  [1] = "[使用GPS卫星进行定位]"
}
jt808_fields.location_basic_status18 = ProtoField.uint32("jt808.location_basic_status18", "GPS", base.HEX, status18, 0x00002000)

local status19 = {
  [0] = "[未使用北斗卫星进行定位]",
  [1] = "[使用北斗卫星进行定位]"
}
jt808_fields.location_basic_status19 = ProtoField.uint32("jt808.location_basic_status19", "BeiDou", base.HEX, status19, 0x00001000)

local status20 = {
  [0] = "[未使用GLONASS卫星进行定位]",
  [1] = "[使用GLONASS卫星进行定位]"
}
jt808_fields.location_basic_status20 = ProtoField.uint32("jt808.location_basic_status20", "GLONASS", base.HEX, status20, 0x00000800)

local status21 = {
  [0] = "[未使用Galileo卫星进行定位]",
  [1] = "[使用Galileo卫星进行定位]"
}
jt808_fields.location_basic_status21 = ProtoField.uint32("jt808.location_basic_status21", "Galileo", base.HEX, status21, 0x00000400)

local status22 = {
  [0] = "[车辆处于停止状态]",
  [1] = "[车辆处于行驶状态]"
}
jt808_fields.location_basic_status22 = ProtoField.uint32("jt808.location_basic_status22", "Status", base.HEX, status22, 0x00000200)

local status_others = {
  [0] = "[RESV]",
  [1] = "[RESV]"
}
jt808_fields.location_basic_status_others = ProtoField.uint32("jt808.location_basic_status_others", "Resv", base.HEX, status_others, 0x000001FF)

-- 纬度
jt808_fields.location_basic_latitude = ProtoField.new("Latitude", "jt808.location_basic_latitude", ftypes.UINT32)
-- 经度
jt808_fields.location_basic_longitude = ProtoField.new("Longitude", "jt808.location_basic_longitude", ftypes.UINT32)
-- 海拔
jt808_fields.location_basic_altitude = ProtoField.new("Altitude", "jt808.location_basic_altitude", ftypes.UINT16)
jt808_fields.location_basic_speed = ProtoField.new("Speed", "jt808.location_basic_speed", ftypes.UINT16)
jt808_fields.location_basic_direction = ProtoField.new("Direction", "jt808.location_basic_direction", ftypes.UINT16)
-- 位置扩展信息

local function dissect_location_info_0200(tvbuf, offset, subtree, end_offset, protocol_version)

    local location_warning_subtree = subtree:add(jt808_fields.location_basic_warning, tvbuf(offset, 4))
    location_warning_subtree:add(jt808_fields.location_basic_warning0, tvbuf(offset, 4))
    location_warning_subtree:add(jt808_fields.location_basic_warning1, tvbuf(offset, 4))
    location_warning_subtree:add(jt808_fields.location_basic_warning2, tvbuf(offset, 4))
    location_warning_subtree:add(jt808_fields.location_basic_warning3, tvbuf(offset, 4))
    location_warning_subtree:add(jt808_fields.location_basic_warning4, tvbuf(offset, 4))
    location_warning_subtree:add(jt808_fields.location_basic_warning5, tvbuf(offset, 4))
    location_warning_subtree:add(jt808_fields.location_basic_warning6, tvbuf(offset, 4))
    location_warning_subtree:add(jt808_fields.location_basic_warning7, tvbuf(offset, 4))
    location_warning_subtree:add(jt808_fields.location_basic_warning8, tvbuf(offset, 4))
    location_warning_subtree:add(jt808_fields.location_basic_warning9, tvbuf(offset, 4))
    location_warning_subtree:add(jt808_fields.location_basic_warning10, tvbuf(offset, 4))
    location_warning_subtree:add(jt808_fields.location_basic_warning11, tvbuf(offset, 4))
    location_warning_subtree:add(jt808_fields.location_basic_warning12, tvbuf(offset, 4))
    location_warning_subtree:add(jt808_fields.location_basic_warning13, tvbuf(offset, 4))
    location_warning_subtree:add(jt808_fields.location_basic_warning14, tvbuf(offset, 4))
    location_warning_subtree:add(jt808_fields.location_basic_warning15, tvbuf(offset, 4))
    location_warning_subtree:add(jt808_fields.location_basic_warning16, tvbuf(offset, 4))
    location_warning_subtree:add(jt808_fields.location_basic_warning17, tvbuf(offset, 4))
    location_warning_subtree:add(jt808_fields.location_basic_warning18, tvbuf(offset, 4))
    location_warning_subtree:add(jt808_fields.location_basic_warning19, tvbuf(offset, 4))
    location_warning_subtree:add(jt808_fields.location_basic_warning20, tvbuf(offset, 4))
    location_warning_subtree:add(jt808_fields.location_basic_warning21, tvbuf(offset, 4))
    location_warning_subtree:add(jt808_fields.location_basic_warning22, tvbuf(offset, 4))
    location_warning_subtree:add(jt808_fields.location_basic_warning23, tvbuf(offset, 4))
    location_warning_subtree:add(jt808_fields.location_basic_warning24, tvbuf(offset, 4))
    location_warning_subtree:add(jt808_fields.location_basic_warning25, tvbuf(offset, 4))
    location_warning_subtree:add(jt808_fields.location_basic_warning26, tvbuf(offset, 4))
    location_warning_subtree:add(jt808_fields.location_basic_warning27, tvbuf(offset, 4))
    location_warning_subtree:add(jt808_fields.location_basic_warning28, tvbuf(offset, 4))
    location_warning_subtree:add(jt808_fields.location_basic_warning29, tvbuf(offset, 4))
    location_warning_subtree:add(jt808_fields.location_basic_warning30, tvbuf(offset, 4))
    location_warning_subtree:add(jt808_fields.location_basic_warning31, tvbuf(offset, 4))
    offset = offset + 4

    local location_status_subtree = subtree:add(jt808_fields.location_basic_status, tvbuf(offset, 4))
    location_status_subtree:add(jt808_fields.location_basic_status0, tvbuf(offset, 4))
    location_status_subtree:add(jt808_fields.location_basic_status1, tvbuf(offset, 4))
    location_status_subtree:add(jt808_fields.location_basic_status2, tvbuf(offset, 4))
    location_status_subtree:add(jt808_fields.location_basic_status3, tvbuf(offset, 4))
    location_status_subtree:add(jt808_fields.location_basic_status4, tvbuf(offset, 4))
    location_status_subtree:add(jt808_fields.location_basic_status5, tvbuf(offset, 4))
    location_status_subtree:add(jt808_fields.location_basic_status6, tvbuf(offset, 4))
    location_status_subtree:add(jt808_fields.location_basic_status7, tvbuf(offset, 4))
    location_status_subtree:add(jt808_fields.location_basic_status8_9, tvbuf(offset, 4))
    location_status_subtree:add(jt808_fields.location_basic_status10, tvbuf(offset, 4))
    location_status_subtree:add(jt808_fields.location_basic_status11, tvbuf(offset, 4))
    location_status_subtree:add(jt808_fields.location_basic_status12, tvbuf(offset, 4))
    location_status_subtree:add(jt808_fields.location_basic_status13, tvbuf(offset, 4))
    location_status_subtree:add(jt808_fields.location_basic_status14, tvbuf(offset, 4))
    location_status_subtree:add(jt808_fields.location_basic_status15, tvbuf(offset, 4))
    location_status_subtree:add(jt808_fields.location_basic_status16, tvbuf(offset, 4))
    location_status_subtree:add(jt808_fields.location_basic_status17, tvbuf(offset, 4))
    location_status_subtree:add(jt808_fields.location_basic_status18, tvbuf(offset, 4))
    location_status_subtree:add(jt808_fields.location_basic_status19, tvbuf(offset, 4))
    location_status_subtree:add(jt808_fields.location_basic_status20, tvbuf(offset, 4))
    location_status_subtree:add(jt808_fields.location_basic_status21, tvbuf(offset, 4))
    location_status_subtree:add(jt808_fields.location_basic_status22, tvbuf(offset, 4))
    location_status_subtree:add(jt808_fields.location_basic_status_others, tvbuf(offset, 4))
    offset = offset + 4

    local latitude, len = get_four_bytes(tvbuf, offset)
    subtree:add(jt808_fields.location_basic_latitude, tvbuf(offset, len), tostring(latitude / 1e6))
    offset = offset + len

    local longtitude, len = get_four_bytes(tvbuf, offset)
    subtree:add(jt808_fields.location_basic_longitude, tvbuf(offset, len), tostring(longtitude / 1e6))
    offset = offset + len

    subtree:add(jt808_fields.location_basic_altitude, tvbuf(offset, 2))
    offset = offset + 2

    local speed, len = get_two_bytes(tvbuf, offset)
    subtree:add(jt808_fields.location_basic_speed, tvbuf(offset, len), tostring(speed / 1e1))
    offset = offset + len

    subtree:add(jt808_fields.location_basic_direction, tvbuf(offset, 2))
    offset = offset + 2

    offset = parse_time(tvbuf, offset, subtree)

    -- Check for unknown fields.
    if end_offset > offset then
        subtree:add(jt808_fields.unknown_fields, tvbuf(offset, end_offset-offset))
        subtree:add_proto_expert_info(found_unknown_fields)
        offset = end_offset
    end

    return offset
end
msg_type_handler[0x0200] = dissect_location_info_0200


---------------------------- 文本信息下发 ----------------------------

jt808_fields.down_text_flag = ProtoField.uint8("jt808.down_text_flag", "Flag", base.HEX)
local down_text_flag_value = {
    [0] = "[Unkown]",
    [1] = "[Service]",
    [2] = "[Emergency]",
    [3] = "[Notify]"
}
jt808_fields.down_text_flag_resv   = ProtoField.uint8("jt808.down_text_flag.type", "Type", base.HEX, down_text_flag_value, 0x03)
jt808_fields.down_text_flag_terminal_display   = ProtoField.uint8("jt808.down_text_flag.terminal_display", "Terminal Display", base.HEX, nil, 0x04)
jt808_fields.down_text_flag_tts = ProtoField.uint8("jt808.down_text_flag.tts", "TTS", base.HEX, nil, 0x08)
jt808_fields.down_text_flag_reserve = ProtoField.uint8("jt808.down_text_flag.reserve", "Reserve", base.HEX, nil, 0x10)
local down_text_info_type_value = {
    [0] = "[Central Navigation Info]",
    [1] = "[Fault Info Code]"
}
jt808_fields.down_text_flag_info_type = ProtoField.uint8("jt808.down_text_flag.info_type", "Info Type", base.HEX, down_text_info_type_value, 0x20)
jt808_fields.down_text_flag_reserve2 = ProtoField.uint8("jt808.down_text_flag.reserve2", "Reserve", base.HEX, nil, 0xC0)
local down_text_type = {
    [1] = "[通知]",
    [2] = "[服务]"
}
jt808_fields.down_text_type = ProtoField.uint8("jt808.down_text_type", "Down Text Type", base.HEX, down_text_type)
jt808_fields.down_text_content = ProtoField.new("Down Text Content", "jt808.down_text_content", ftypes.STRING)

local function dissect_down_text_8300(tvbuf, offset, subtree, end_offset, protocol_version)

    local flag_subtree =subtree:add(jt808_fields.down_text_flag, tvbuf(offset, 1))
    flag_subtree:add(jt808_fields.down_text_flag_reserve2, tvbuf(offset, 1))
    flag_subtree:add(jt808_fields.down_text_flag_info_type, tvbuf(offset, 1))
    flag_subtree:add(jt808_fields.down_text_flag_reserve, tvbuf(offset, 1))
    flag_subtree:add(jt808_fields.down_text_flag_tts, tvbuf(offset, 1))
    flag_subtree:add(jt808_fields.down_text_flag_terminal_display, tvbuf(offset, 1))
    flag_subtree:add(jt808_fields.down_text_flag_resv, tvbuf(offset, 1))
    offset = offset + 1

    subtree:add(jt808_fields.down_text_type, tvbuf(offset, 1))
    offset = offset + 1

    -- Message.
    local down_text_content_len = end_offset-offset
    local down_text, len = get_gbk_string(tvbuf, offset, down_text_content_len)
    subtree.add(jt808_fields.down_text_content, tvbuf(offset, len), down_text)
    offset = offset + len
    
    -- Check for unknown fields.
    if end_offset > offset then
        subtree:add(jt808_fields.unknown_fields, tvbuf(offset, end_offset-offset))
        subtree:add_proto_expert_info(found_unknown_fields)
        offset = end_offset
    end

    return offset
end
msg_type_handler[0x8300] = dissect_down_text_8300

-------------------------------parse function-------------------------------------------------

local function get_msg_type(tvbuf, offset, subtree)
    local type, len = get_two_bytes(tvbuf, offset)
    subtree:add(jt808_fields.msg_type, tvbuf(offset, len))
    return offset + len, type
end

local function get_msg_attr(buffer, offset, subtree)
    local msg_attr, len = get_two_bytes(buffer, offset)
    local msg_attr_subtree =subtree:add(jt808_fields.msg_attr, buffer(offset, len))
    msg_attr_subtree:add(jt808_fields.msg_attr_length, buffer(offset, len))
    msg_attr_subtree:add(jt808_fields.msg_attr_secure, buffer(offset, len))
    msg_attr_subtree:add(jt808_fields.msg_attr_flag, buffer(offset, len))
    msg_attr_subtree:add(jt808_fields.msg_attr_version_flag, buffer(offset, len))
    msg_attr_subtree:add(jt808_fields.msg_attr_resv, buffer(offset, len))
    return offset + len, bit32.band(msg_attr, 0x03FF), bit32.band(msg_attr, 0x2000), bit32.band(msg_attr, 0x4000)
end

local function get_sub_pkg(buffer, offset, subtree)
    subtree:add(jt808_fields.sub_pkg_cnt, buffer(offset, 2))
    offset = offset + 2
    subtree:add(jt808_fields.sub_pkg_idx, buffer(offset, 2))
    return offset + 2
end

local function get_terminal_phone_number(buffer, offset, subtree, protocol_version)
    local len = 6
    if protocol_version == 1 then
        len = 10
    end
    local terminal_phone, phone_len = get_bcd_string(buffer, offset, len)
    subtree:add(jt808_fields.terminal_phone_number, buffer(offset, phone_len), terminal_phone)
    return offset + phone_len
end

local function get_msg_seq(buffer, offset, subtree)
    local seq_id, len = get_two_bytes(buffer, offset)
    subtree:add(jt808_fields.msg_seq_no, buffer(offset, len))
    return offset + len, seq_id
end

local function get_crc(buffer, offset, subtree)
    local data, len = get_one_byte(buffer, offset)
    subtree:add(jt808_fields.crc, buffer(offset, len))
    return offset + len
end

local function dissect_jt808(tvbuf, offset, subtree, pinfo)
    subtree:add(jt808_fields.flag, tvbuf(offset, 1))
    offset = offset + 1

    local start_pos = offset
    local header_tree = subtree:add(JT808_proto, tvbuf(offset), "JT808 Header")
    local offset, msg_type = get_msg_type(tvbuf, offset, pinfo)
    local offset, payload_length, version_flag, has_sub_pkg = get_msg_attr(tvbuf, offset, header_tree)
    local protocol_version = 0
    if version_flag == 0 then
        offset = get_terminal_phone_number(tvbuf, offset, header_tree, protocol_version)
    else
        protocol_version, _ = get_one_byte(tvbuf, offset)
        header_tree:add(jt808_fields.protocol_version, tvbuf(offset, 1))
        offset = offset + 1
        offset = get_terminal_phone_number(tvbuf, offset, 10, header_tree, protocol_version)
    end
    local offset, seq_id = get_msg_seq(tvbuf, offset, header_tree)
    if has_sub_pkg then
        offset = get_sub_pkg(tvbuf, offset, header_tree)
    end
    header_tree:set_len(offset - start_pos)
    -- Add cols info.
    pinfo.cols.info = string.format("%s (0x%04x) [v%d] Seq=%d\t", msg_type[msg_type], msg_type, protocol_version, seq_id)

    local handler = msg_type_handler[msg_type]
    local body_tree = subtree:add(JT808_proto, tvbuf(offset, payload_length), "JT808 Body")
    if handler ~= nil then
        offset = handler(tvbuf, offset, body_tree, offset + payload_length, protocol_version)
    else
        offset = offset + payload_length
        body_tree:add_proto_expert_info(no_body_handler)
    end
    offset = get_crc(tvbuf, offset, subtree)
    subtree:add(jt808_fields.flag, tvbuf(offset, 1))
end

local function jt808_unescape(tvbuf, start_pos, end_pos, idx)
    -- print(string.format('Start = %d, end = %d', start_pos, end_pos))
    local raw_buf = tvbuf:raw(start_pos, end_pos-start_pos+1)
    -- print(string.format('Before unescape raw_buf len = %d', raw_buf:len()))
    -- Optmize unescape using gsub.
    raw_buf = string.gsub(raw_buf, '\x7d[\x01\x02]', function (escaped_char)
        if escaped_char == '\x7d\x01' then
            return '\x7d'
        else
            return '\x7e'
        end
    end)
    -- print(string.format('After unescape raw_buf len = %d', raw_buf:len()))
    return ByteArray.tvb(ByteArray.new(raw_buf, true), string.format("Escaped JT808 Frame %d", idx))
end


local function dissect(tvbuf, pktinfo, root, offset, origlen, idx)
    -- Find start flag.
    local i = offset
    local valid_start = false

    local pktlen = origlen - offset

    while i < origlen do
        if get_one_byte(tvbuf, i) == 0x7e and i < origlen - 1 and get_one_byte(tvbuf, i) ~= 0x7e then
            valid_start = true
            break
        else
            i = i + 1
        end
    end
    -- We are at the start, check size.
    if (not valid_start) or (origlen - i < JT808_MSG_LEN_POS_LEN) then
        -- We don't know how many bytes we need, just ask for another segment.
        pktinfo.desegment_offset = i
        pktinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
        return 0, DESEGMENT_ONE_MORE_SEGMENT
    end
    -- Load size.
    local msg_len = bit32.band(get_two_bytes(tvbuf, i+3), 0x03ff)

    -- According to GBT protocol, max message size should be no more than 1024.
    if msg_len > 1024 then
        -- Too many bytes, invalid message
        print("JT808 message length is too long: ", msg_len)
        return pktlen, 0
    end

    if origlen - i < msg_len + 2 then
        -- We need msg_len + 2 - (origlen - i) bytes.
        pktinfo.desegment_offset = i
        pktinfo.desegment_len = (msg_len + 2 - origlen + i)
        return 0, -pktinfo.desegment_len
    end

    -- Verify for end_flag.
    local j = i + msg_len + 1
    local valid_end = false
    while j < origlen do
        if get_one_byte(tvbuf, j) == 0x7e then
            valid_end = true
            break
        else
            j = j + 1
        end
    end
    if not valid_end then
        -- we need more bytes
        pktinfo.desegment_offset = i
        pktinfo.desegment_len = 1
        return 0, -pktinfo.desegment_len
    end

    -- set the protocol column to show our protocol name
    pktinfo.cols.protocol:set("JT808")
    local unescape_tvbuf = jt808_unescape(tvbuf, i, j, idx)

    local subtree = root:add(JT808_proto, unescape_tvbuf, tostring(idx))
    dissect_jt808(unescape_tvbuf, 0, subtree, pktinfo)

    return j - offset + 1, 0
end

function JT808_proto.dissector(tvbuf, pktinfo, root)
    -- Get the length of the packet tvbuf (Tvb).
    local pktlen = tvbuf:len()
    local offset, bytes_needed = 0, 0

    local bytes_consumed = 0
    local idx = 0
    while bytes_consumed < pktlen do
        offset, bytes_needed = dissect(tvbuf, pktinfo, root, bytes_consumed, pktlen, idx)
        print(string.format('Offset = %d, bytes_needed = %d, pktlen = %d', offset, bytes_needed, pktlen))
        if offset == 0 then
            if bytes_consumed > 0 then
                return bytes_consumed
            else
                return bytes_needed
            end
        end
        idx = idx + 1
        bytes_consumed = bytes_consumed + offset
    end

    return bytes_consumed
end


local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(1983, JT808_proto)
-- tcp_table:add(8010, JT808_proto)
-- You can add other tcp port 
-- tcp_table:add(XXXX, jt808_proto)

local udp_table = DissectorTable.get("udp.port")
udp_table:add(1983, JT808_proto)
-- You can add other udp port 
-- udp_table:add(XXXX, jt808_proto)
