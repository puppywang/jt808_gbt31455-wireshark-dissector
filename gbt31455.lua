local bit32 = require "bit32"

GBT31455_proto = Proto("gbt31455", "GBT31455 Protocol")
GBT31455_proto.fields = {}
local gbt31455_fields = GBT31455_proto.fields
-- Start flag
gbt31455_fields.start_flag = ProtoField.uint8("gbt31455.start_flag", "Start Flag", base.HEX)
gbt31455_fields.end_flag = ProtoField.uint8("gbt31455.end_flag", "End Flag", base.HEX)
-- Header fields.
gbt31455_fields.hdr_msg_length = ProtoField.uint16("gbt31455.msg_length", "Msg Length", base.DEC)
gbt31455_fields.hdr_version = ProtoField.new("Version", "gbt31455.version", ftypes.STRING)
local hdr_field = {
    [1] = '[车载设备]',
    [2] = '[调度中心]',
    [3] = '[场站车站设备]'
}
gbt31455_fields.hdr_field =  ProtoField.uint8("gbt31455.field", "Field", base.HEX, hdr_field)
gbt31455_fields.hdr_seq_id =  ProtoField.uint8("gbt31455.seq_id", "Seq ID", base.DEC)
gbt31455_fields.hdr_src_addr  = ProtoField.uint32("gbt31455.src_addr", "Src Addr", base.DEC)
gbt31455_fields.hdr_dst_addr  = ProtoField.uint32("gbt31455.dst_addr", "Dst Addr", base.DEC)
local msg_type = {
    [0x01] = '[VtLogin]',
    [0x02] = '[VtLoginAck]',
    [0x03] = '[VtLogout]',
    [0x04] = '[VtAck]',
    [0x05] = '[VtShakeHands]',
    [0x06] = '[VtLocationReport]',
    [0x07] = '[VtAlarm]',
    [0x08] = '[VtAttendance]',
    [0x23] = '[VtAttendanceAck]',
    [0x09] = '[VtDispatchMessage]',
    [0x0A] = '[VtOperatorMessage]',
    [0x0B] = '[VtTimeReviseRequest]',
    [0x0C] = '[VtTimeReviseAck]',
    [0x0D] = '[VtLocationRequest]',
    [0x0F] = '[VtDepartMessage]',
    [0x10] = '[VtSecheduleRequest]',
    [0x11] = '[VtPushSchedule]',
    [0x12] = '[VtBusinessRegister]',
    [0x13] = '[VtBusinessInstruction]',
    [0x14] = '[VtBusinessRequest]',
    [0x15] = '[VtBusinessRequestAck]',
    [0x16] = '[VtArrLeavStop]',
    [0x17] = '[VtNotifyUpgrade]',
    [0x18] = '[VtUpgradeComplete]',
    [0x19] = '[VtShutDownReport]',
    [0x1A] = '[VtDevMalReport]',
    [0x1B] = '[VtInfoPublish]',
    [0x1C] = '[VtInfoQuery]',
    [0x1D] = '[VtInfoQueryAck]',
    [0x1E] = '[VtMonitorRequest]',
    [0x1F] = '[VtMonitorAck]',
    [0x20] = '[VtRemoteControl]',
    [0x21] = '[VtThirdPartyDataUp]',
    [0x22] = '[VtThirdPartyDataDown]',
    [0x24] = '[VtInOutDepot]',
    [0x25] = '[VtViolationReport]'
}
gbt31455_fields.hdr_msg_type = ProtoField.uint8("gbt31455.msg_type", "Message Type", base.HEX, msg_type)
gbt31455_fields.body_param_cnt = ProtoField.uint8("gbt31455.param_cnt", "Param Count", base.DEC)
gbt31455_fields.crc = ProtoField.uint8("gbt31455.crc", "CRC", base.HEX)
gbt31455_fields.fields_ctls = ProtoField.new("Fields Ctrls", "gbt31455.fields_ctls", ftypes.STRING)
gbt31455_fields.fields_length = ProtoField.uint16("gbt31455.fields_length", "Fields Length", base.DEC)

gbt31455_fields.unknown_fields = ProtoField.new("Unknown Fields", "gbt31455.unknown_fields", ftypes.BYTES)
-- Export info.
local found_unknown_fields = ProtoExpert.new("gbt31455.expert.unknown_fields", "Found Unknown Fields", expert.group.MALFORMED, expert.severity.WARN)
local no_body_handler = ProtoExpert.new("gbt31455.expert.no_body_handler", "No body handler", expert.group.PROTOCOL, expert.severity.WARN)
GBT31455_proto.experts = { found_unknown_fields, no_body_handler }

-- Mininal buf length that we can determine msg_len.
local GBT31455_MSG_LEN_POS_LEN = 3

------------------------------- Common parse function-------------------------------------------------

local function get_one_byte(tvbuf, offset)
    return tvbuf(offset, 1):uint(), 1
end

local function get_two_bytes(tvbuf, offset)
    return tvbuf(offset, 2):uint(), 2
end

local function get_four_bytes(tvbuf, offset)
    return tvbuf(offset, 4):uint(), 4
end

local function get_gbk_string(tvbuf, offset, length)
    return tvbuf(offset, length):string(ENC_GB18030), length
end

local function get_var_len(tvbuf, offset)
    local var_len, len = get_one_byte(tvbuf, offset)
    if var_len < 128 then
        return var_len, 1
    end
    offset = offset + len
    local var_len_2, len = get_one_byte(tvbuf, offset)
    if var_len_2 < 128 then
        return bit32.band(var_len, 0x7f) + bit32.lshift(bit32.band(var_len_2, 0x7f), 7), 2
    end
    offset = offset + len
    local var_len_3, _ = get_one_byte(tvbuf, offset)
    return bit32.band(var_len, 0x7f) + bit32.lshift(bit32.band(var_len_2, 0x7f), 7) + bit32.lshift(var_len_3, 14), 3
end

local function get_var_gbk_string(tvbuf, offset)
    local var_len, len = get_var_len(tvbuf, offset)
    local string, str_len = get_gbk_string(tvbuf, offset + len, var_len)
    return string, len + str_len
end

local bool_string_map = {
    [false] = 'N',
    [true] = 'Y'
}
local function format_fields_ctls(fields_ctls)
    local fields_ctls_str = ''
    for _, v in pairs(fields_ctls) do
        fields_ctls_str = fields_ctls_str .. ', ' .. bool_string_map[v]
    end
    return string.sub(fields_ctls_str, 2)
end

local function parse_fields_ctls_and_data_len(tvbuf, offset, subtree, new_subtree_name, data_len)
    local fields_ctls = {}
    local offset_start = offset
    while true do
        local fields_ctl, len = get_one_byte(tvbuf, offset)
        for i = 0, 6 do
            table.insert(fields_ctls, bit32.band(fields_ctl, bit32.lshift(1, i)) == bit32.lshift(1, i))
        end
        offset = offset + len
        if fields_ctl < 128 then
            -- Collect data_len
            local new_subtree
            if data_len == 0 then
                local data_len, len = get_two_bytes(tvbuf, offset)
                new_subtree = subtree:add(GBT31455_proto, tvbuf(offset_start, offset - offset_start + len + data_len), new_subtree_name)
                new_subtree:add(gbt31455_fields.fields_ctls, tvbuf(offset_start, offset-offset_start), format_fields_ctls(fields_ctls))
                new_subtree:add(gbt31455_fields.fields_length, tvbuf(offset, len))
                offset = offset + len
            else
                new_subtree = subtree:add(GBT31455_proto, tvbuf(offset_start, data_len), new_subtree_name)
                new_subtree:add(gbt31455_fields.fields_ctls, tvbuf(offset_start, offset-offset_start), format_fields_ctls(fields_ctls))
            end
            return offset, new_subtree, fields_ctls
        end
    end
end

---------------------------- VTDeviceIden ----------------------------

gbt31455_fields.device_id = ProtoField.uint32("gbt31455.device_id", "Device ID", base.DEC)
gbt31455_fields.corp_id = ProtoField.uint16("gbt31455.corp_id", "Corp ID", base.DEC)
gbt31455_fields.internal_vehicle_id = ProtoField.new("Internal Vehicle ID", "gbt31455.internal_vehicle_id", ftypes.STRING)
gbt31455_fields.license_no = ProtoField.new("License No", "gbt31455.license_no", ftypes.STRING)
gbt31455_fields.manufacturer_id = ProtoField.uint8("gbt31455.manufacturer_id", "Manufacturer ID", base.DEC)
gbt31455_fields.device_model = ProtoField.uint8("gbt31455.device_model", "Device Model", base.DEC)

local function parse_vt_vehicle_iden(tvbuf, offset, subtree)
    local offset, vehicle_subtree, fields_ctls = parse_fields_ctls_and_data_len(tvbuf, offset, subtree, "VT Vehicle Iden", 0)
    if fields_ctls[1] then
        vehicle_subtree:add(gbt31455_fields.device_id, tvbuf(offset, 4))
        offset = offset + 4
    end
    if fields_ctls[2] then
        vehicle_subtree:add(gbt31455_fields.corp_id, tvbuf(offset, 2))
        offset = offset + 2
    end
    if fields_ctls[3] then
        local internal_vehicle_id, len = get_var_gbk_string(tvbuf, offset)
        vehicle_subtree:add(gbt31455_fields.internal_vehicle_id, tvbuf(offset, len), tostring(internal_vehicle_id))
        offset = offset + len
    end
    if fields_ctls[4] then
        local license_no, len = get_var_gbk_string(tvbuf, offset)
        vehicle_subtree:add(gbt31455_fields.license_no, tvbuf(offset, len), tostring(license_no))
        offset = offset + len
    end
    if fields_ctls[5] then
        vehicle_subtree:add(gbt31455_fields.manufacturer_id, tvbuf(offset, 1))
        offset = offset + 1
    end
    if fields_ctls[6] then
        vehicle_subtree:add(gbt31455_fields.device_model, tvbuf(offset, 1))
        offset = offset + 1
    end
    return offset
end

---------------------------- VTRouteIden ----------------------------

gbt31455_fields.line_id = ProtoField.uint32("gbt31455.line_id", "Line ID", base.DEC)
gbt31455_fields.subline_id = ProtoField.uint32("gbt31455.subline_id", "SubLine ID", base.DEC)
gbt31455_fields.line_name = ProtoField.new("Line Name", "gbt31455.line_name", ftypes.STRING)

local function parse_vt_route_iden(tvbuf, offset, subtree)
    local offset, vt_route_iden_subtree, fields_ctls = parse_fields_ctls_and_data_len(tvbuf, offset, subtree, "VT Route Iden", 0)
    if fields_ctls[1] then
        vt_route_iden_subtree:add(gbt31455_fields.line_id, tvbuf(offset, 4))
        offset = offset + 4
    end
    if fields_ctls[2] then
        vt_route_iden_subtree:add(gbt31455_fields.subline_id, tvbuf(offset, 4))
        offset = offset + 4
    end
    if fields_ctls[3] then
        local line_name, len = get_var_gbk_string(tvbuf, offset)
        vt_route_iden_subtree:add(gbt31455_fields.line_name, tvbuf(offset, len), tostring(line_name))
        offset = offset + len
    end
    return offset
end

---------------------------- VTGeoDynamicPoint ----------------------------

gbt31455_fields.latitude = ProtoField.new("Latitude", "gbt31455.latitude", ftypes.STRING)
gbt31455_fields.longtiude = ProtoField.new("Longtiude", "gbt31455.longtiude", ftypes.STRING)
gbt31455_fields.altitude = ProtoField.uint16("gbt31455.altitude", "Altitude", base.DEC)
gbt31455_fields.angle = ProtoField.uint16("gbt31455.angle", "Angle", base.DEC)
gbt31455_fields.speed = ProtoField.new("Speed", "gbt31455.speed", ftypes.STRING)
gbt31455_fields.gps_valid = ProtoField.bool("gbt31455.gps_valid", "GPS Valid")

local function parse_speed(tvbuf, offset, subtree)
    local speed, len = get_two_bytes(tvbuf, offset)
    subtree:add(gbt31455_fields.speed, tvbuf(offset, len), tostring(speed / 100))
    return offset + len
end

local function parse_vt_geo_dynamic_point(tvbuf, offset, subtree)
    local offset, geo_dynamic_point_subtree, fields_ctls = parse_fields_ctls_and_data_len(tvbuf, offset, subtree, "VT Geo Dynamic Point", 0)
    if fields_ctls[1] then
        local latitude, len = get_four_bytes(tvbuf, offset)
        geo_dynamic_point_subtree:add(gbt31455_fields.latitude, tvbuf(offset, len), tostring(latitude / 1e6))
        offset = offset + len
    end
    if fields_ctls[2] then
        local longtitude, len = get_four_bytes(tvbuf, offset)
        geo_dynamic_point_subtree:add(gbt31455_fields.longtiude, tvbuf(offset, len), tostring(longtitude / 1e6))
        offset = offset + len
    end
    if fields_ctls[3] then
        geo_dynamic_point_subtree:add(gbt31455_fields.altitude, tvbuf(offset, 2))
        offset = offset + 2
    end
    if fields_ctls[4] then
        geo_dynamic_point_subtree:add(gbt31455_fields.angle, tvbuf(offset, 2))
        offset = offset + 2
    end
    if fields_ctls[5] then
        offset = parse_speed(tvbuf, offset, geo_dynamic_point_subtree)
    end
    if fields_ctls[6] then
        geo_dynamic_point_subtree:add(gbt31455_fields.gps_valid, tvbuf(offset, 1))
        offset = offset + 1
    end
    return offset
end

------------------------------- VTVersionIden ------------------------------------------
-- Add enum for version type.
gbt31455_fields.version_type = ProtoField.uint8("gbt31455.version_type", "Version Type", base.DEC)
gbt31455_fields.version = ProtoField.new("Version", "gbt31455.version", ftypes.STRING)

local function parse_vt_version_iden(tvbuf, offset, subtree)
    local offset, vt_version_iden_subtree, fields_ctls = parse_fields_ctls_and_data_len(tvbuf, offset, subtree, "VT Version Iden", 0)
    if fields_ctls[1] then
        vt_version_iden_subtree:add(gbt31455_fields.version_type, tvbuf(offset, 1))
        offset = offset + 1
    end
    if fields_ctls[2] then
        local version, len = get_var_gbk_string(tvbuf, offset)
        vt_version_iden_subtree:add(gbt31455_fields.version, tvbuf(offset, len), tostring(version))
        offset = offset + len
    end
    return offset
end

------------------------------- VTEmployeeIden ------------------------------------------
gbt31455_fields.employee_no = ProtoField.new("Employee No.", "gbt31455.employee_no", ftypes.STRING)
local vt_employee_type = {
    [1] = "[驾驶员]",
    [2] = "[乘务员]",
    [3] = "[站务员]",
    [4] = "[调度员]",
}
gbt31455_fields.employee_type = ProtoField.uint8("gbt31455.employee_type", "Employee Type", base.HEX, vt_employee_type)
gbt31455_fields.employee_name = ProtoField.new("Employee Name", "gbt31455.employee_name", ftypes.STRING)
gbt31455_fields.employee_id = ProtoField.new("Employee ID", "gbt31455.employee_id", ftypes.STRING)
gbt31455_fields.employee_card_no = ProtoField.new("Employee Card No.", "gbt31455.employee_card_no", ftypes.STRING)

local function parse_vt_employee_iden(tvbuf, offset, subtree)
    local offset, vt_employee_iden_subtree, fields_ctls = parse_fields_ctls_and_data_len(tvbuf, offset, subtree, "VT Employee Iden", 0)
    if fields_ctls[1] then
        local employee_no, len = get_var_gbk_string(tvbuf, offset)
        vt_employee_iden_subtree:add(gbt31455_fields.employee_no, tvbuf(offset, len), employee_no)
        offset = offset + len
    end
    if fields_ctls[2] then
        vt_employee_iden_subtree:add(gbt31455_fields.employee_type, tvbuf(offset, 1))
        offset = offset + 1
    end
    if fields_ctls[3] then
        local employee_name, len = get_var_gbk_string(tvbuf, offset)
        vt_employee_iden_subtree:add(gbt31455_fields.employee_name, tvbuf(offset, len), tostring(employee_name))
        offset = offset + len
    end
    if fields_ctls[4] then
        local employee_id, len = get_var_gbk_string(tvbuf, offset)
        vt_employee_iden_subtree:add(gbt31455_fields.employee_id, tvbuf(offset, len), tostring(employee_id))
        offset = offset + len
    end
    if fields_ctls[5] then
        local employee_card_no, len = get_var_gbk_string(tvbuf, offset)
        vt_employee_iden_subtree:add(gbt31455_fields.employee_card_no, tvbuf(offset, len), tostring(employee_card_no))
        offset = offset + len
    end
    return offset
end

gbt31455_fields.time = ProtoField.new("Timestamp", "gbt31455.time", ftypes.ABSOLUTE_TIME)

local function parse_time(tvbuf, offset, subtree)
    subtree:add(gbt31455_fields.time, tvbuf(offset, 4))
    return offset + 4
end

------------------------------- VTStopIden ------------------------------------------

gbt31455_fields.stop_id = ProtoField.uint32("gbt31455.stop_id", "Stop ID", base.DEC)
local vt_stop_type = {
    [1] = "[起点站]",
    [2] = "[中途站]",
    [3] = "[终点站]",
    [4] = "[考核站]",
    [5] = "[公交优先点]",
    [0x80] = "[主站场]",
    [0x81] = "[副站场]",
    [0x82] = "[停车场]",
    [0x83] = "[维修厂]",
    [0x84] = "[加油站]",
}
gbt31455_fields.vt_stop_type = ProtoField.uint8("gbt31455.vt_stop_type", "VT Stop Type", base.HEX, vt_stop_type)
gbt31455_fields.stop_index = ProtoField.uint32("gbt31455.stop_index", "Stop Index", base.DEC)
gbt31455_fields.stop_name = ProtoField.new("Stop Name", "gbt31455.stop_name", ftypes.STRING)

local function parse_vt_stop_iden(tvbuf, offset, subtree, msg_name)
    if msg_name == nil then
        msg_name = "VT Stop Iden"
    end
    local offset, vt_stop_iden_subtree, fields_ctls = parse_fields_ctls_and_data_len(tvbuf, offset, subtree, msg_name, 0)
    if fields_ctls[1] then
        vt_stop_iden_subtree:add(gbt31455_fields.stop_id, tvbuf(offset, 4))
        offset = offset + 4
    end
    if fields_ctls[2] then
        vt_stop_iden_subtree:add(gbt31455_fields.vt_stop_type, tvbuf(offset, 1))
        offset = offset + 1
    end
    if fields_ctls[3] then
        vt_stop_iden_subtree:add(gbt31455_fields.stop_index, tvbuf(offset, 1))
        offset = offset + 1
    end
    if fields_ctls[4] then
        local stop_name, len = get_var_gbk_string(tvbuf, offset)
        vt_stop_iden_subtree:add(gbt31455_fields.stop_name, tvbuf(offset, len), tostring(stop_name))
        offset = offset + len
    end
    return offset
end

------------------------------- VTPassengerCount ------------------------------------------

gbt31455_fields.current_passenger_cnt = ProtoField.uint16("gbt31455.current_passenger_cnt", "Current Passenger Count", base.DEC)
gbt31455_fields.gate_1_passenger_boarding_cnt = ProtoField.uint8("gbt31455.gate_1_passenger_boarding_cnt", "Gate 1 Passenger Boarding Count", base.DEC)
gbt31455_fields.gate_1_passenger_get_off_cnt = ProtoField.uint8("gbt31455.gate_1_passenger_get_off_cnt", "Gate 1 Passenger Get Off Count", base.DEC)
gbt31455_fields.gate_2_passenger_boarding_cnt = ProtoField.uint8("gbt31455.gate_2_passenger_boarding_cnt", "Gate 2 Passenger Boarding Count", base.DEC)
gbt31455_fields.gate_2_passenger_get_off_cnt = ProtoField.uint8("gbt31455.gate_2_passenger_get_off_cnt", "Gate 2 Passenger Get Off Count", base.DEC)
gbt31455_fields.gate_3_passenger_boarding_cnt = ProtoField.uint8("gbt31455.gate_3_passenger_boarding_cnt", "Gate 3 Passenger Boarding Count", base.DEC)
gbt31455_fields.gate_3_passenger_get_off_cnt = ProtoField.uint8("gbt31455.gate_3_passenger_get_off_cnt", "Gate 3 Passenger Get Off Count", base.DEC)
gbt31455_fields.gate_4_passenger_boarding_cnt = ProtoField.uint8("gbt31455.gate_4_passenger_boarding_cnt", "Gate 4 Passenger Boarding Count", base.DEC)
gbt31455_fields.gate_4_passenger_get_off_cnt = ProtoField.uint8("gbt31455.gate_4_passenger_get_off_cnt", "Gate 4 Passenger Get Off Count", base.DEC)
gbt31455_fields.gate_5_passenger_boarding_cnt = ProtoField.uint8("gbt31455.gate_5_passenger_boarding_cnt", "Gate 5 Passenger Boarding Count", base.DEC)
gbt31455_fields.gate_5_passenger_get_off_cnt = ProtoField.uint8("gbt31455.gate_5_passenger_get_off_cnt", "Gate 5 Passenger Get Off Count", base.DEC)
gbt31455_fields.gate_6_passenger_boarding_cnt = ProtoField.uint8("gbt31455.gate_6_passenger_boarding_cnt", "Gate 6 Passenger Boarding Count", base.DEC)
gbt31455_fields.gate_6_passenger_get_off_cnt = ProtoField.uint8("gbt31455.gate_6_passenger_get_off_cnt", "Gate 6 Passenger Get Off Count", base.DEC)

local function parse_vt_passenger_count(tvbuf, offset, subtree)
    local offset, vt_passenger_count_subtree, fields_ctls = parse_fields_ctls_and_data_len(tvbuf, offset, subtree, "VT Passenger Count", 0)
    if fields_ctls[1] then
        vt_passenger_count_subtree:add(gbt31455_fields.current_passenger_cnt, tvbuf(offset, 2))
        offset = offset + 2
    end
    if fields_ctls[2] then
        vt_passenger_count_subtree:add(gbt31455_fields.gate_1_passenger_boarding_cnt, tvbuf(offset, 1))
        offset = offset + 1
    end
    if fields_ctls[3] then
        vt_passenger_count_subtree:add(gbt31455_fields.gate_1_passenger_get_off_cnt, tvbuf(offset, 1))
        offset = offset + 1
    end
    if fields_ctls[4] then
        vt_passenger_count_subtree:add(gbt31455_fields.gate_2_passenger_boarding_cnt, tvbuf(offset, 1))
        offset = offset + 1
    end
    if fields_ctls[5] then
        vt_passenger_count_subtree:add(gbt31455_fields.gate_2_passenger_get_off_cnt, tvbuf(offset, 1))
        offset = offset + 1
    end
    if fields_ctls[6] then
        vt_passenger_count_subtree:add(gbt31455_fields.gate_3_passenger_boarding_cnt, tvbuf(offset, 1))
        offset = offset + 1
    end
    if fields_ctls[7] then
        vt_passenger_count_subtree:add(gbt31455_fields.gate_3_passenger_get_off_cnt, tvbuf(offset, 1))
        offset = offset + 1
    end
    if fields_ctls[8] then
        vt_passenger_count_subtree:add(gbt31455_fields.gate_4_passenger_boarding_cnt, tvbuf(offset, 1))
        offset = offset + 1
    end
    if fields_ctls[9] then
        vt_passenger_count_subtree:add(gbt31455_fields.gate_4_passenger_get_off_cnt, tvbuf(offset, 1))
        offset = offset + 1
    end
    if fields_ctls[10] then
        vt_passenger_count_subtree:add(gbt31455_fields.gate_5_passenger_boarding_cnt, tvbuf(offset, 1))
        offset = offset + 1
    end
    if fields_ctls[11] then
        vt_passenger_count_subtree:add(gbt31455_fields.gate_5_passenger_get_off_cnt, tvbuf(offset, 1))
        offset = offset + 1
    end
    if fields_ctls[12] then
        vt_passenger_count_subtree:add(gbt31455_fields.gate_6_passenger_boarding_cnt, tvbuf(offset, 1))
        offset = offset + 1
    end
    if fields_ctls[13] then
        vt_passenger_count_subtree:add(gbt31455_fields.gate_6_passenger_get_off_cnt, tvbuf(offset, 1))
        offset = offset + 1
    end
    return offset
end

local vt_violation_type = {
    [1] = "[超速行车]",
    [2] = "[低速行车]",
    [3] = "[滞站]",
    [4] = "[越站]",
    [5] = "[车内温度过高]",
    [6] = "[车内温度过低]",
    [7] = "[急减速]",
    [8] = "[急加速]",
    [9] = "[疲劳驾驶]",
    [0xA] = "[超载]",
    [0xB] = "[越界行驶]",
}
gbt31455_fields.vt_violation_type = ProtoField.uint8("gbt31455.vt_violation_type", "VT Violation Type", base.HEX, vt_violation_type)
gbt31455_fields.violation_value = ProtoField.uint16("gbt31455.violation_value", "Violation Value", base.DEC)
gbt31455_fields.violation_standard = ProtoField.uint16("gbt31455.violation_standard", "Violation Standard", base.DEC)
gbt31455_fields.violation_note = ProtoField.new("Violation Note", "gbt31455.violation_standard", ftypes.STRING)

local function parse_vt_violation(tvbuf, offset, subtree)
    local offset, vt_violation_subtree, fields_ctls = parse_fields_ctls_and_data_len(tvbuf, offset, subtree, "VT Violation", 0)
    if fields_ctls[1] then
        vt_violation_subtree:add(gbt31455_fields.vt_violation_type, tvbuf(offset, 1))
        offset = offset + 1
    end
    if fields_ctls[2] then
        vt_violation_subtree:add(gbt31455_fields.violation_value, tvbuf(offset, 2))
        offset = offset + 2
    end
    if fields_ctls[3] then
        vt_violation_subtree:add(gbt31455_fields.violation_standard, tvbuf(offset, 2))
        offset = offset + 2
    end
    if fields_ctls[4] then
        local violation_note, len = get_var_gbk_string(tvbuf, offset)
        vt_violation_subtree:add(gbt31455_fields.violation_note, tvbuf(offset, len), violation_note)
        offset = offset + len
    end
    return offset
end

------------------------------ Sub message handlers ------------------------------

local msg_type_handler = {}

----------------------------------- VtLogin ---------------------------------------

local vt_login_type = {
    [1] = "[加电登录]",
    [2] = "[重启登录]",
    [3] = "[重连登录]",
    [4] = "[调换线路]",
}
gbt31455_fields.login_type = ProtoField.uint8("gbt31455.login_type", "Login Type", base.HEX, vt_login_type)

gbt31455_fields.version_cnt = ProtoField.new("Version Count", "gbt31455.version_cnt", ftypes.STRING)

gbt31455_fields.login_password = ProtoField.new("Login Password", "gbt31455.login_password", ftypes.STRING)

local vt_mno_type = {
    [1] = "[中国移动]",
    [2] = "[中国联通]",
    [3] = "[中国电信]",
}
gbt31455_fields.mno_type = ProtoField.uint8("gbt31455.mno_type", "Mobile Network Operator Type", base.HEX, vt_mno_type)

local vt_net_type = {
    [1] = "[GSM/GPRS]",
    [2] = "[CDMA]",
    [3] = "[TD-SCDMA]",
    [4] = "[WCDMA]",
    [5] = "[EVDO]",
}
gbt31455_fields.net_type = ProtoField.uint8("gbt31455.net_type", "Network Type", base.HEX, vt_net_type)

local function dissect_vt_login(tvbuf, offset, subtree, end_offset)
    local offset, login_subtree, fields_ctls = parse_fields_ctls_and_data_len(tvbuf, offset, subtree, "VT Login", end_offset-offset)
    if fields_ctls[1] then
        offset = parse_vt_vehicle_iden(tvbuf, offset, login_subtree)
    end
    if fields_ctls[2] then
        offset = parse_time(tvbuf, offset, login_subtree)
    end
    if fields_ctls[3] then
        login_subtree:add(gbt31455_fields.login_type, tvbuf(offset, 1))
        offset = offset + 1
    end
    if fields_ctls[4] then
        offset = parse_vt_route_iden(tvbuf, offset, login_subtree)
    end
    if fields_ctls[5] then
        local password, len = get_var_gbk_string(tvbuf, offset)
        login_subtree:add(gbt31455_fields.login_password, tvbuf(offset, len), string(password))
    end
    if fields_ctls[6] then
        local ver_cnt, len = get_var_len(tvbuf, offset)
        login_subtree.add(gbt31455_fields.version_cnt, tvbuf(offset, len), string(ver_cnt))
        offset = offset + len
        for _ = 1, ver_cnt do
            offset = parse_vt_version_iden(tvbuf, offset, login_subtree)
        end
    end
    if fields_ctls[7] then
        offset = parse_vt_geo_dynamic_point(tvbuf, offset, login_subtree)
    end
    if fields_ctls[8] then
        login_subtree:add(gbt31455_fields.mno_type, tvbuf(offset, 1))
        offset = offset + 1
    end
    if fields_ctls[9] then
        login_subtree:add(gbt31455_fields.net_type, tvbuf(offset, 1))
        offset = offset + 1
    end

    -- Check for unknown fields.
    if end_offset > offset then
        login_subtree:add(gbt31455_fields.unknown_fields, tvbuf(offset, end_offset-offset))
        login_subtree:add_proto_expert_info(found_unknown_fields)
        offset = end_offset
    end

    return offset
end
msg_type_handler[0x01] = dissect_vt_login

----------------------------------- VtLoginAck ---------------------------------------

gbt31455_fields.ack_seq_id = ProtoField.uint8("gbt31455.ack_seq_id", "ACK Seq ID", base.DEC)

local vt_login_result = {
    [1] = "[登录成功]",
    [2] = "[源地址冲突]",
    [3] = "[源地址无效，为系统保留]",
    [4] = "[验证失败，密码错误等]",
}
gbt31455_fields.vt_login_result = ProtoField.uint8("gbt31455.vt_login_result", "VT Login Result", base.HEX, vt_login_result)

gbt31455_fields.handshake_interval = ProtoField.uint16("gbt31455.handshake_interval", "Handshake Interval", base.DEC)

local function dissect_vt_login_ack(tvbuf, offset, subtree, end_offset)
    local offset, login_ack_subtree, fields_ctls = parse_fields_ctls_and_data_len(tvbuf, offset, subtree, "VT Login Ack", end_offset-offset)
    if fields_ctls[1] then
        login_ack_subtree:add(gbt31455_fields.ack_seq_id, tvbuf(offset, 1))
        offset = offset + 1
    end
    if fields_ctls[2] then
        login_ack_subtree:add(gbt31455_fields.vt_login_result, tvbuf(offset, 1))
        offset = offset + 1
    end
    if fields_ctls[3] then
        login_ack_subtree:add(gbt31455_fields.handshake_interval, tvbuf(offset, 2))
        offset = offset + 2
    end

    -- Check for unknown fields.
    if end_offset > offset then
        login_ack_subtree:add(gbt31455_fields.unknown_fields, tvbuf(offset, end_offset-offset))
        login_ack_subtree:add_proto_expert_info(found_unknown_fields)
        offset = end_offset
    end

    return offset
end
msg_type_handler[0x02] = dissect_vt_login_ack

----------------------------------- VtLogout ---------------------------------------

local function dissect_vt_logout(tvbuf, offset, subtree, end_offset)
    local offset, logout_subtree, fields_ctls = parse_fields_ctls_and_data_len(tvbuf, offset, subtree, "VT Logout", end_offset-offset)
    if fields_ctls[1] then
        offset = parse_vt_vehicle_iden(tvbuf, offset, logout_subtree)
    end
    if fields_ctls[2] then
        offset = parse_time(tvbuf, offset, logout_subtree)
    end
    if fields_ctls[3] then
        offset = parse_vt_geo_dynamic_point(tvbuf, offset, logout_subtree)
    end

    -- Check for unknown fields.
    if end_offset > offset then
        logout_subtree:add(gbt31455_fields.unknown_fields, tvbuf(offset, end_offset-offset))
        logout_subtree:add_proto_expert_info(found_unknown_fields)
        offset = end_offset
    end

    return offset
end
msg_type_handler[0x03]= dissect_vt_logout

----------------------------------- VtAck ---------------------------------------

gbt31455_fields.ack_msg_type = ProtoField.uint8("gbt31455.ack_msg_type", "ACK Message Type", base.HEX, msg_type)

local vt_ack_code = {
    [1] = "[已收到]",
    [2] = "[已接受]",
    [3] = "[被拒绝]",
    [4] = "[校验错误]",
    [5] = "[暂停业务数据上传]",
    [6] = "[回复业务数据上传]",
}
gbt31455_fields.vt_ack_code = ProtoField.uint8("gbt31455.vt_ack_code", "VT ACK Code", base.HEX, vt_ack_code)

gbt31455_fields.err_msg = ProtoField.new("Error Message", "gbt31455.err_msg", ftypes.STRING)

local function dissect_vt_ack(tvbuf, offset, subtree, end_offset)
    local offset, ack_subtree, fields_ctls = parse_fields_ctls_and_data_len(tvbuf, offset, subtree, "VT Ack", end_offset-offset)
    if fields_ctls[1] then
        offset = parse_vt_vehicle_iden(tvbuf, offset, ack_subtree)
    end
    if fields_ctls[2] then
        ack_subtree:add(gbt31455_fields.ack_msg_type, tvbuf(offset, 1))
        offset = offset + 1
    end
    if fields_ctls[3] then
        ack_subtree:add(gbt31455_fields.ack_seq_id, tvbuf(offset, 1))
        offset = offset + 1
    end
    if fields_ctls[4] then
        ack_subtree:add(gbt31455_fields.vt_ack_code, tvbuf(offset, 1))
        offset = offset + 1
    end
    if fields_ctls[5] then
        local err_msg, len = get_var_gbk_string(tvbuf, offset)
        ack_subtree:add(gbt31455_fields.err_msg, tvbuf(offset, len), string(err_msg))
        offset = offset + len
    end
    if fields_ctls[6] then
        offset = parse_time(tvbuf, offset, ack_subtree)
    end

    -- Check for unknown fields.
    if end_offset > offset then
        ack_subtree:add(gbt31455_fields.unknown_fields, tvbuf(offset, end_offset-offset))
        ack_subtree:add_proto_expert_info(found_unknown_fields)
        offset = end_offset
    end

    return offset
end
msg_type_handler[0x04] = dissect_vt_ack

----------------------------------- VtShakeHands ---------------------------------------

local function dissect_vt_shake_hands(tvbuf, offset, subtree, end_offset)
    local offset, shake_hands_subtree, fields_ctls = parse_fields_ctls_and_data_len(tvbuf, offset, subtree, "VT Shake Hands", end_offset-offset)
    if fields_ctls[1] then
        shake_hands_subtree:add(gbt31455_fields.handshake_interval, tvbuf(offset, 2))
        offset = offset + 2
    end

    -- Check for unknown fields.
    if end_offset > offset then
        shake_hands_subtree:add(gbt31455_fields.unknown_fields, tvbuf(offset, end_offset-offset))
        shake_hands_subtree:add_proto_expert_info(found_unknown_fields)
        offset = end_offset
    end

    return offset
end
msg_type_handler[0x05] = dissect_vt_shake_hands

----------------------------------- VtLocationReport ---------------------------------------

local vt_loc_rep_reason = {
    [1] = "[定时上报]",
    [2] = "[定距上报]",
    [3] = "[点名上报]",
    [4] = "[车辆开门]",
    [5] = "[车辆关门]",
}
gbt31455_fields.vt_loc_rep_reason = ProtoField.uint8("gbt31455.vt_loc_rep_reason", "VT Location Report Reason", base.HEX, vt_loc_rep_reason)

gbt31455_fields.vehicle_state = ProtoField.uint32("gbt31455.vehicle_state", "Vehicle State", base.HEX)
local vehicle_state_0 = {
    [0] = "[1号门关]",
    [1] = "[1号门开]"
}
gbt31455_fields.vehicle_state_0 = ProtoField.uint32("gbt31455.vehicle_state_0", "Vehicle State Bit 0", base.HEX, vehicle_state_0, 0x00000001)
local vehicle_state_1 = {
    [0] = "[2号门关]",
    [1] = "[2号门开]"
}
gbt31455_fields.vehicle_state_1 = ProtoField.uint32("gbt31455.vehicle_state_1", "Vehicle State Bit 1", base.HEX, vehicle_state_1, 0x00000002)
local vehicle_state_2 = {
    [0] = "[3号门关]",
    [1] = "[3号门开]"
}
gbt31455_fields.vehicle_state_2 = ProtoField.uint32("gbt31455.vehicle_state_2", "Vehicle State Bit 2", base.HEX, vehicle_state_2, 0x00000004)
local vehicle_state_3 = {
    [0] = "[4号门关]",
    [1] = "[4号门开]"
}
gbt31455_fields.vehicle_state_3 = ProtoField.uint32("gbt31455.vehicle_state_3", "Vehicle State Bit 3", base.HEX, vehicle_state_3, 0x00000008)
local vehicle_state_4 = {
    [0] = "[5号门关]",
    [1] = "[5号门开]"
}
gbt31455_fields.vehicle_state_4 = ProtoField.uint32("gbt31455.vehicle_state_4", "Vehicle State Bit 4", base.HEX, vehicle_state_4, 0x00000010)
local vehicle_state_5 = {
    [0] = "[6号门关]",
    [1] = "[6号门开]"
}
gbt31455_fields.vehicle_state_5 = ProtoField.uint32("gbt31455.vehicle_state_5", "Vehicle State Bit 5", base.HEX, vehicle_state_5, 0x00000020)
local vehicle_state_6 = {
    [0] = "[ACC关]",
    [1] = "[ACC开]"
}
gbt31455_fields.vehicle_state_6 = ProtoField.uint32("gbt31455.vehicle_state_6", "Vehicle State Bit 6", base.HEX, vehicle_state_6, 0x00000040)
local vehicle_state_7 = {
    [0] = "[主电路断电]",
    [1] = "[主电路通电]"
}
gbt31455_fields.vehicle_state_7 = ProtoField.uint32("gbt31455.vehicle_state_7", "Vehicle State Bit 7", base.HEX, vehicle_state_7, 0x00000080)
local vehicle_state_8 = {
    [0] = "[后节牌正常]",
    [1] = "[后节牌故障]"
}
gbt31455_fields.vehicle_state_8 = ProtoField.uint32("gbt31455.vehicle_state_8", "Vehicle State Bit 8", base.HEX, vehicle_state_8, 0x00000100)
local vehicle_state_9 = {
    [0] = "[前节牌正常]",
    [1] = "[前节牌故障]"
}
gbt31455_fields.vehicle_state_9 = ProtoField.uint32("gbt31455.vehicle_state_9", "Vehicle State Bit 9", base.HEX, vehicle_state_9, 0x00000200)
local vehicle_state_10 = {
    [0] = "[后路牌正常]",
    [1] = "[后路牌故障]"
}
gbt31455_fields.vehicle_state_10 = ProtoField.uint32("gbt31455.vehicle_state_10", "Vehicle State Bit 10", base.HEX, vehicle_state_10, 0x00000400)
local vehicle_state_11 = {
    [0] = "[腰牌正常]",
    [1] = "[腰牌故障]"
}
gbt31455_fields.vehicle_state_11 = ProtoField.uint32("gbt31455.vehicle_state_11", "Vehicle State Bit 11", base.HEX, vehicle_state_11, 0x00000800)
local vehicle_state_12 = {
    [0] = "[前路牌正常]",
    [1] = "[前路牌故障]"
}
gbt31455_fields.vehicle_state_12 = ProtoField.uint32("gbt31455.vehicle_state_12", "Vehicle State Bit 12", base.HEX, vehicle_state_12, 0x00001000)
local vehicle_state_13 = {
    [0] = "[中屏正常]",
    [1] = "[中屏故障]"
}
gbt31455_fields.vehicle_state_13 = ProtoField.uint32("gbt31455.vehicle_state_13", "Vehicle State Bit 13", base.HEX, vehicle_state_13, 0x00002000)
local vehicle_state_14 = {
    [0] = "[头屏正常]",
    [1] = "[头屏故障]"
}
gbt31455_fields.vehicle_state_14 = ProtoField.uint32("gbt31455.vehicle_state_14", "Vehicle State Bit 14", base.HEX, vehicle_state_14, 0x00004000)
local vehicle_state_15 = {
    [0] = "[报站器正常]",
    [1] = "[报站器故障]"
}
gbt31455_fields.vehicle_state_15 = ProtoField.uint32("gbt31455.vehicle_state_15", "Vehicle State Bit 15", base.HEX, vehicle_state_15, 0x00008000)
local vehicle_state_16 = {
    [0] = "[485总线正常]",
    [1] = "[485总线故障]"
}
gbt31455_fields.vehicle_state_16 = ProtoField.uint32("gbt31455.vehicle_state_16", "Vehicle State Bit 16", base.HEX, vehicle_state_16, 0x00010000)
local vehicle_state_17 = {
    [0] = "[CAN总线正常]",
    [1] = "[CAN总线异常]"
}
gbt31455_fields.vehicle_state_17 = ProtoField.uint32("gbt31455.vehicle_state_17", "Vehicle State Bit 17", base.HEX, vehicle_state_17, 0x00020000)
local vehicle_state_18 = {
    [0] = "[通信模块正常]",
    [1] = "[通信模块故障]"
}
gbt31455_fields.vehicle_state_18 = ProtoField.uint32("gbt31455.vehicle_state_18", "Vehicle State Bit 18", base.HEX, vehicle_state_18, 0x00040000)
local vehicle_state_19 = {
    [0] = "[卫星定位模块正常]",
    [1] = "[卫星定位模块故障]"
}
gbt31455_fields.vehicle_state_19 = ProtoField.uint32("gbt31455.vehicle_state_19", "Vehicle State Bit 19", base.HEX, vehicle_state_19, 0x00080000)

gbt31455_fields.vehicle_temp = ProtoField.uint16("gbt31455.vehicle_temp", "Vehicle Temp", base.DEC)
gbt31455_fields.accumulate_distance = ProtoField.uint32("gbt31455.accumulate_distance", "Accumulate Distance", base.DEC)
local vt_service_type = {
    [1] = "[上行]",
    [2] = "[下行]",
    [3] = "[环形]",
    [4] = "[停主站]",
    [5] = "[停副站]",
}
gbt31455_fields.vt_service_type = ProtoField.uint8("gbt31455.vt_service_type", "VT Service Type", base.HEX, vt_service_type)
gbt31455_fields.trip_no = ProtoField.uint8("gbt31455.trip_no", "Trip No", base.DEC)
local vt_resend_flag = {
    [1] = "[正常数据]",
    [2] = "[补发数据]",
}
gbt31455_fields.vt_resend_flag = ProtoField.uint8("gbt31455.vt_resend_flag", "VT Resend Flag", base.HEX, vt_resend_flag)

local function parse_vehicle_state(tvbuf, offset, subtree)
  local vehicle_state_subtree = subtree:add(gbt31455_fields.vehicle_state, tvbuf(offset, 4))
  vehicle_state_subtree:add(gbt31455_fields.vehicle_state_0, tvbuf(offset, 4))
  vehicle_state_subtree:add(gbt31455_fields.vehicle_state_1, tvbuf(offset, 4))
  vehicle_state_subtree:add(gbt31455_fields.vehicle_state_2, tvbuf(offset, 4))
  vehicle_state_subtree:add(gbt31455_fields.vehicle_state_3, tvbuf(offset, 4))
  vehicle_state_subtree:add(gbt31455_fields.vehicle_state_4, tvbuf(offset, 4))
  vehicle_state_subtree:add(gbt31455_fields.vehicle_state_5, tvbuf(offset, 4))
  vehicle_state_subtree:add(gbt31455_fields.vehicle_state_6, tvbuf(offset, 4))
  vehicle_state_subtree:add(gbt31455_fields.vehicle_state_7, tvbuf(offset, 4))
  vehicle_state_subtree:add(gbt31455_fields.vehicle_state_8, tvbuf(offset, 4))
  vehicle_state_subtree:add(gbt31455_fields.vehicle_state_9, tvbuf(offset, 4))
  vehicle_state_subtree:add(gbt31455_fields.vehicle_state_10, tvbuf(offset, 4))
  vehicle_state_subtree:add(gbt31455_fields.vehicle_state_11, tvbuf(offset, 4))
  vehicle_state_subtree:add(gbt31455_fields.vehicle_state_12, tvbuf(offset, 4))
  vehicle_state_subtree:add(gbt31455_fields.vehicle_state_13, tvbuf(offset, 4))
  vehicle_state_subtree:add(gbt31455_fields.vehicle_state_14, tvbuf(offset, 4))
  vehicle_state_subtree:add(gbt31455_fields.vehicle_state_15, tvbuf(offset, 4))
  vehicle_state_subtree:add(gbt31455_fields.vehicle_state_16, tvbuf(offset, 4))
  vehicle_state_subtree:add(gbt31455_fields.vehicle_state_17, tvbuf(offset, 4))
  vehicle_state_subtree:add(gbt31455_fields.vehicle_state_18, tvbuf(offset, 4))
  vehicle_state_subtree:add(gbt31455_fields.vehicle_state_19, tvbuf(offset, 4))

  return offset + 4
end

local function parse_vehicle_temp(tvbuf, offset, subtree)
    subtree:add(gbt31455_fields.vehicle_temp, tvbuf(offset, 2))
    return offset + 2
end

local function parse_accumulate_distance(tvbuf, offset, subtree)
    subtree:add(gbt31455_fields.accumulate_distance, tvbuf(offset, 4))
    return offset + 4
end

local function parse_vt_service_type(tvbuf, offset, subtree)
    subtree:add(gbt31455_fields.vt_service_type, tvbuf(offset, 1))
    return offset + 1
end

local function parse_trip_no(tvbuf, offset, subtree)
    subtree:add(gbt31455_fields.trip_no, tvbuf(offset, 2))
    return offset + 2
end

local function parse_vt_resend_flag(tvbuf, offset, subtree)
    subtree:add(gbt31455_fields.vt_resend_flag, tvbuf(offset, 1))
    return offset + 1
end

local function dissect_vt_location_report(tvbuf, offset, subtree, end_offset)
    local offset, location_report_subtree, fields_ctls = parse_fields_ctls_and_data_len(tvbuf, offset, subtree, "VT Location Report", end_offset-offset)
    if fields_ctls[1] then
        offset = parse_vt_vehicle_iden(tvbuf, offset, location_report_subtree)
    end
    if fields_ctls[2] then
        offset = parse_vt_route_iden(tvbuf, offset, location_report_subtree)
    end
    if fields_ctls[3] then
        offset = parse_vt_employee_iden(tvbuf, offset, location_report_subtree)
    end
    if fields_ctls[4] then
        location_report_subtree:add(gbt31455_fields.vt_loc_rep_reason, tvbuf(offset, 1))
        offset = offset + 1
    end
    if fields_ctls[5] then
        offset = parse_time(tvbuf, offset, location_report_subtree)
    end
    if fields_ctls[6] then
        offset = parse_vt_geo_dynamic_point(tvbuf, offset, location_report_subtree)
    end
    if fields_ctls[7] then
        offset = parse_vehicle_state(tvbuf, offset, location_report_subtree)
    end
    if fields_ctls[8] then
        offset = parse_speed(tvbuf, offset, location_report_subtree)
    end
    if fields_ctls[9] then
        offset = parse_vehicle_temp(tvbuf, offset, location_report_subtree)
    end
    if fields_ctls[10] then
        offset = parse_accumulate_distance(tvbuf, offset, location_report_subtree)
    end
    if fields_ctls[11] then
        offset = parse_vt_service_type(tvbuf, offset, location_report_subtree)
    end
    if fields_ctls[12] then
        offset = parse_trip_no(tvbuf, offset, location_report_subtree)
    end
    if fields_ctls[13] then
        offset = parse_vt_stop_iden(tvbuf, offset, location_report_subtree)
    end
    if fields_ctls[14] then
        offset = parse_vt_stop_iden(tvbuf, offset, location_report_subtree, "Next VT Stop Iden")
    end
    if fields_ctls[15] then
        offset = parse_vt_resend_flag(tvbuf, offset, location_report_subtree)
    end

    -- Check for unknown fields.
    if end_offset > offset then
        location_report_subtree:add(gbt31455_fields.unknown_fields, tvbuf(offset, end_offset-offset))
        location_report_subtree:add_proto_expert_info(found_unknown_fields)
        offset = end_offset
    end

    return offset
end
msg_type_handler[0x06] = dissect_vt_location_report


----------------------------------- VtArrLeavStop ---------------------------------------

local vt_arr_leav_stop_type = {
    [1] = "[到站]",
    [2] = "[离站]",
}
gbt31455_fields.vt_arr_leav_stop_type = ProtoField.uint8("gbt31455.vt_arr_leav_stop_type", "VT Arrive Leave Stop Type", base.HEX, vt_arr_leav_stop_type)

gbt31455_fields.arr_leav_stop_flag = ProtoField.uint8("gbt31455.arr_leav_stop_flag", "Arrive Leave Stop Flag", base.HEX)
local arr_leav_stop_flag_0 = {
    [0] = "[自动报站]",
    [1] = "[手动报站]"
}
gbt31455_fields.arr_leav_stop_flag_0 = ProtoField.uint8("gbt31455.arr_leav_stop_flag_0", "Arrive Leave Stop Flag Bit 0", base.HEX, arr_leav_stop_flag_0, 0x01)

local function parse_arr_leav_stop_flag(tvbuf, offset, subtree)
    local arr_lave_stop_flag_subtree = subtree:add(gbt31455_fields.arr_leav_stop_flag, tvbuf(offset, 1))
    arr_lave_stop_flag_subtree:add(gbt31455_fields.arr_leav_stop_flag_0, tvbuf(offset, 1))

    return offset + 1
end

local function dissect_vt_arr_leav_stop(tvbuf, offset, subtree, end_offset)
    local offset, vt_arrive_leave_subtree, fields_ctls = parse_fields_ctls_and_data_len(tvbuf, offset, subtree, "VT Arrive Leave Stop", end_offset-offset)
    if fields_ctls[1] then
        offset = parse_vt_vehicle_iden(tvbuf, offset, vt_arrive_leave_subtree)
    end
    if fields_ctls[2] then
        offset = parse_vt_route_iden(tvbuf, offset, vt_arrive_leave_subtree)
    end
    if fields_ctls[3] then
        offset = parse_vt_employee_iden(tvbuf, offset, vt_arrive_leave_subtree)
    end
    if fields_ctls[4] then
        vt_arrive_leave_subtree:add(gbt31455_fields.vt_arr_leav_stop_type, tvbuf(offset, 1))
        offset = offset + 1
    end
    if fields_ctls[5] then
        offset = parse_time(tvbuf, offset, vt_arrive_leave_subtree)
    end
    if fields_ctls[6] then
        offset = parse_vt_geo_dynamic_point(tvbuf, offset, vt_arrive_leave_subtree)
    end
    if fields_ctls[7] then
        offset = parse_vehicle_state(tvbuf, offset, vt_arrive_leave_subtree)
    end
    if fields_ctls[8] then
        offset = parse_speed(tvbuf, offset, vt_arrive_leave_subtree)
    end
    if fields_ctls[9] then
        offset = parse_vehicle_temp(tvbuf, offset, vt_arrive_leave_subtree)
    end
    if fields_ctls[10] then
        offset = parse_accumulate_distance(tvbuf, offset, vt_arrive_leave_subtree)
    end
    if fields_ctls[11] then
        offset = parse_vt_service_type(tvbuf, offset, vt_arrive_leave_subtree)
    end
    if fields_ctls[12] then
        offset = parse_trip_no(tvbuf, offset, vt_arrive_leave_subtree)
    end
    if fields_ctls[13] then
        offset = parse_vt_stop_iden(tvbuf, offset, vt_arrive_leave_subtree)
    end
    if fields_ctls[14] then
        offset = parse_vt_stop_iden(tvbuf, offset, vt_arrive_leave_subtree, "Next VT Stop Iden")
    end
    if fields_ctls[15] then
        offset = parse_vt_passenger_count(tvbuf, offset, vt_arrive_leave_subtree)
    end
    if fields_ctls[16] then
        offset = parse_arr_leav_stop_flag(tvbuf, offset, vt_arrive_leave_subtree)
    end
    if fields_ctls[17] then
        offset = parse_vt_resend_flag(tvbuf, offset, vt_arrive_leave_subtree)
    end

    -- Check for unknown fields.
    if end_offset > offset then
        vt_arrive_leave_subtree:add(gbt31455_fields.unknown_fields, tvbuf(offset, end_offset-offset))
        vt_arrive_leave_subtree:add_proto_expert_info(found_unknown_fields)
        offset = end_offset
    end

    return offset
end
msg_type_handler[0x16] = dissect_vt_arr_leav_stop

----------------------------------- VtViolationReport ---------------------------------------

local function dissect_vt_violation_report(tvbuf, offset, subtree, end_offset)
    local offset, vt_violation_report_subtree, fields_ctls = parse_fields_ctls_and_data_len(tvbuf, offset, subtree, "VT Violation Report", end_offset-offset)
    if fields_ctls[1] then
        offset = parse_vt_vehicle_iden(tvbuf, offset, vt_violation_report_subtree)
    end
    if fields_ctls[2] then
        offset = parse_vt_route_iden(tvbuf, offset, vt_violation_report_subtree)
    end
    if fields_ctls[3] then
        offset = parse_vt_employee_iden(tvbuf, offset, vt_violation_report_subtree)
    end
    if fields_ctls[4] then
        offset = parse_time(tvbuf, offset, vt_violation_report_subtree)
    end
    if fields_ctls[5] then
        offset = parse_vt_violation(tvbuf, offset, vt_violation_report_subtree)
    end
    if fields_ctls[6] then
        offset = parse_vt_geo_dynamic_point(tvbuf, offset, vt_violation_report_subtree)
    end
    if fields_ctls[7] then
        offset = parse_vehicle_state(tvbuf, offset, vt_violation_report_subtree)
    end
    if fields_ctls[8] then
        offset = parse_speed(tvbuf, offset, vt_violation_report_subtree)
    end
    if fields_ctls[9] then
        offset = parse_vehicle_temp(tvbuf, offset, vt_violation_report_subtree)
    end
    if fields_ctls[10] then
        offset = parse_accumulate_distance(tvbuf, offset, vt_violation_report_subtree)
    end
    if fields_ctls[11] then
        offset = parse_vt_service_type(tvbuf, offset, vt_violation_report_subtree)
    end
    if fields_ctls[12] then
        offset = parse_trip_no(tvbuf, offset, vt_violation_report_subtree)
    end
    if fields_ctls[13] then
        offset = parse_vt_stop_iden(tvbuf, offset, vt_violation_report_subtree)
    end
    if fields_ctls[14] then
        offset = parse_vt_stop_iden(tvbuf, offset, vt_violation_report_subtree, "Next VT Stop Iden")
    end
    if fields_ctls[15] then
        offset = parse_vt_resend_flag(tvbuf, offset, vt_violation_report_subtree)
    end

    -- Check for unknown fields.
    if end_offset > offset then
        vt_violation_report_subtree:add(gbt31455_fields.unknown_fields, tvbuf(offset, end_offset-offset))
        vt_violation_report_subtree:add_proto_expert_info(found_unknown_fields)
        offset = end_offset
    end

    return offset
end

msg_type_handler[0x25] = dissect_vt_violation_report


----------------------------------- VtBusinessRequest ---------------------------------------

local vt_business_request_type = {
    [1] = "[请求排班]",
    [2] = "[请求交班]",
    [3] = "[请求吃饭]",
    [4] = "[请求加油]",
}
gbt31455_fields.vt_business_request_type = ProtoField.uint8("gbt31455.vt_business_request_type", "VT Business Request Type", base.HEX, vt_business_request_type)

local function dissect_vt_business_request(tvbuf, offset, subtree, end_offset)
    local offset, vt_business_request_subtree, fields_ctls = parse_fields_ctls_and_data_len(tvbuf, offset, subtree, "VT Business Report", end_offset-offset)

    if fields_ctls[1] then
        offset = parse_vt_vehicle_iden(tvbuf, offset, vt_business_request_subtree)
    end
    if fields_ctls[2] then
        offset = parse_vt_route_iden(tvbuf, offset, vt_business_request_subtree)
    end
    if fields_ctls[3] then
        offset = parse_vt_employee_iden(tvbuf, offset, vt_business_request_subtree)
    end
    if fields_ctls[4] then
        vt_business_request_subtree:add(gbt31455_fields.vt_business_request_type, tvbuf(offset, 1))
        offset = offset + 1
    end
    if fields_ctls[5] then
        offset = parse_time(tvbuf, offset, vt_business_request_subtree)
    end

    -- Check for unknown fields.
    if end_offset > offset then
        vt_business_request_subtree:add(gbt31455_fields.unknown_fields, tvbuf(offset, end_offset-offset))
        vt_business_request_subtree:add_proto_expert_info(found_unknown_fields)
        offset = end_offset
    end

    return offset
end

msg_type_handler[0x14] = dissect_vt_business_request


----------------------------------- VtShutDownReport ---------------------------------------

local function dissect_vt_shutdown_report(tvbuf, offset, subtree, end_offset)
    local offset, vt_shutdown_report_subtree, fields_ctls = parse_fields_ctls_and_data_len(tvbuf, offset, subtree, "VT ShutDown Report", end_offset-offset)

    if fields_ctls[1] then
        offset = parse_vt_vehicle_iden(tvbuf, offset, vt_shutdown_report_subtree)
    end
    if fields_ctls[2] then
        offset = parse_vt_route_iden(tvbuf, offset, vt_shutdown_report_subtree)
    end
    if fields_ctls[3] then
        offset = parse_time(tvbuf, offset, vt_shutdown_report_subtree)
    end

    -- Check for unknown fields.
    if end_offset > offset then
        vt_shutdown_report_subtree:add(gbt31455_fields.unknown_fields, tvbuf(offset, end_offset-offset))
        vt_shutdown_report_subtree:add_proto_expert_info(found_unknown_fields)
        offset = end_offset
    end

    return offset
end

msg_type_handler[0x19] = dissect_vt_shutdown_report


------------------------------- Separate parser functions -------------------------------------------------

local function get_msg_type(tvbuf, offset, subtree)
    subtree:add(gbt31455_fields.hdr_field, tvbuf(offset, 1))
    offset = offset + 1
    local type, len = get_one_byte(tvbuf, offset)
    subtree:add(gbt31455_fields.hdr_msg_type, tvbuf(offset, len))
    return offset + len, type
end

local function get_msg_hdr_attr_pre_type(tvbuf, offset, subtree)
    local msg_len, len = get_two_bytes(tvbuf, offset)
    subtree:add(gbt31455_fields.hdr_msg_length, tvbuf(offset, len))
    offset = offset + len
    local version, len = get_one_byte(tvbuf, offset)
    subtree:add(gbt31455_fields.hdr_version, tvbuf(offset, len), string.format('%d.%d', bit32.rshift(bit32.band(version, 0xf0), 4), bit32.band(version, 0x0f)))
    return offset + len, msg_len
end

local function get_msg_hdr_attr_post_type(tvbuf, offset, subtree, type)
    local seq_id, len = get_one_byte(tvbuf, offset)
    subtree:add(gbt31455_fields.hdr_seq_id, tvbuf(offset, len))
    offset = offset + len
    local src_addr, len = get_four_bytes(tvbuf, offset)
    subtree:add(gbt31455_fields.hdr_src_addr, tvbuf(offset, len))
    offset = offset + len
    local dst_addr, len = get_four_bytes(tvbuf, offset)
    subtree:add(gbt31455_fields.hdr_dst_addr, tvbuf(offset, len))
    return offset + len, string.format("%d → %d %s (0x%02x) Seq=%d\t", src_addr, dst_addr, msg_type[type], type, seq_id)
end

local function get_crc(tvbuf, offset, subtree)
    local crc, len = get_one_byte(tvbuf, offset)
    subtree:add(gbt31455_fields.crc, tvbuf(offset, len), tostring(crc))
    return offset + len
end

local function dissect_gbt31455(tvbuf, offset, subtree, pinfo)
    subtree:add(gbt31455_fields.start_flag, tvbuf(offset, 1))
    offset = offset + 1

    local start_pos = offset
    local header_tree = subtree:add(GBT31455_proto, tvbuf(offset), "GBT31455 Header")
    local offset, msg_len = get_msg_hdr_attr_pre_type(tvbuf, offset, header_tree)
    local offset, msg_type = get_msg_type(tvbuf, offset, header_tree)
    local offset, msg_type_info = get_msg_hdr_attr_post_type(tvbuf, offset, header_tree, msg_type)
    header_tree:set_len(offset - start_pos)
    pinfo.cols.info = msg_type_info

    local handler = msg_type_handler[msg_type]
    local body_msg_len = msg_len - (offset - start_pos) - 1
    local body_tree = subtree:add(GBT31455_proto, tvbuf(offset, body_msg_len), "GBT31455 Body")
    if handler ~= nil then
        offset = handler(tvbuf, offset, body_tree, offset + body_msg_len)
    else
        offset = offset + body_msg_len
        body_tree:add_proto_expert_info(no_body_handler)
    end
    offset = get_crc(tvbuf, offset, subtree)
    subtree:add(gbt31455_fields.end_flag, tvbuf(offset, 1))
end

local function gbt31455_unescape(tvbuf, start_pos, end_pos, idx)
    -- print(string.format('Start = %d, end = %d', start_pos, end_pos))
    local raw_buf = tvbuf:raw(start_pos, end_pos-start_pos+1)
    -- print(string.format('Before unescape raw_buf len = %d', raw_buf:len()))
    -- Optmize unescape using gsub.
    raw_buf = string.gsub(raw_buf, '\x7d[\x5d\x5e\x5f]', function (escaped_char)
        if escaped_char == '\x7d\x5d' then
            return '\x7d'
        elseif escaped_char == '\x7d\x5e' then
            return '\x7e'
        else
            return '\x7f'
        end
    end)
    -- print(string.format('After unescape raw_buf len = %d', raw_buf:len()))
    return ByteArray.tvb(ByteArray.new(raw_buf, true), string.format("Escaped GB31455 Frame %d", idx))
end

local function dissect(tvbuf, pktinfo, root, offset, origlen, idx)
    -- Find start flag.
    local i = offset
    local valid_start = false

    local pktlen = origlen - offset

    while i < origlen do
        if get_one_byte(tvbuf, i) == 0x7e then
            valid_start = true
            break
        else
            i = i + 1
        end
    end
    -- We are at the start, check size.
    if (not valid_start) or (origlen - i < GBT31455_MSG_LEN_POS_LEN) then
        -- We don't know how many bytes we need, just ask for another segment.
        pktinfo.desegment_offset = i
        pktinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
        return 0, DESEGMENT_ONE_MORE_SEGMENT
    end
    -- Load size.
    local msg_len = get_two_bytes(tvbuf, i+1)

    -- According to GBT protocol, max message size should be no more than 1024.
    if msg_len > 1024 then
        -- Too many bytes, invalid message
        print("GBT31455 message length is too long: ", msg_len)
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
        if get_one_byte(tvbuf, j) == 0x7f then
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
    pktinfo.cols.protocol:set("GBT31455")
    local unescape_tvbuf = gbt31455_unescape(tvbuf, i, j, idx)

    local subtree = root:add(GBT31455_proto, unescape_tvbuf, tostring(idx))
    dissect_gbt31455(unescape_tvbuf, 0, subtree, pktinfo)

    return j - offset + 1, 0
end

function GBT31455_proto.dissector(tvbuf, pktinfo, root)
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
tcp_table:add(1983, GBT31455_proto)
-- We proxy all GBT31455 traffic to 8010.
tcp_table:add(8010, GBT31455_proto)
-- You can add other tcp port 
-- tcp_table:add(XXXX, gbt31455_proto)

local udp_table = DissectorTable.get("udp.port")
udp_table:add(1983, GBT31455_proto)
-- You can add other udp port 
-- udp_table:add(XXXX, gbt31455_proto)
