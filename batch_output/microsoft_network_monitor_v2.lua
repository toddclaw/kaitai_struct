microsoft_network_monitor_v2_proto = Proto("kaitai_microsoft_network_monitor_v2","microsoft_network_monitor_v2 file")

local f = microsoft_network_monitor_v2_proto.fields

-- field declarations
f.signature = ProtoField.bytes("microsoft_network_monitor_v2.signature", "signature")
f.version_minor = ProtoField.bytes("microsoft_network_monitor_v2.version_minor", "version_minor")
f.version_major = ProtoField.bytes("microsoft_network_monitor_v2.version_major", "version_major")
f.mac_type = ProtoField.bytes("microsoft_network_monitor_v2.mac_type", "mac_type")
f.time_capture_start = ProtoField.bytes("microsoft_network_monitor_v2.time_capture_start", "time_capture_start")
f.frame_table_ofs = ProtoField.bytes("microsoft_network_monitor_v2.frame_table_ofs", "frame_table_ofs")
f.frame_table_len = ProtoField.bytes("microsoft_network_monitor_v2.frame_table_len", "frame_table_len")
f.user_data_ofs = ProtoField.bytes("microsoft_network_monitor_v2.user_data_ofs", "user_data_ofs")
f.user_data_len = ProtoField.bytes("microsoft_network_monitor_v2.user_data_len", "user_data_len")
f.comment_ofs = ProtoField.bytes("microsoft_network_monitor_v2.comment_ofs", "comment_ofs")
f.comment_len = ProtoField.bytes("microsoft_network_monitor_v2.comment_len", "comment_len")
f.statistics_ofs = ProtoField.bytes("microsoft_network_monitor_v2.statistics_ofs", "statistics_ofs")
f.statistics_len = ProtoField.bytes("microsoft_network_monitor_v2.statistics_len", "statistics_len")
f.network_info_ofs = ProtoField.bytes("microsoft_network_monitor_v2.network_info_ofs", "network_info_ofs")
f.network_info_len = ProtoField.bytes("microsoft_network_monitor_v2.network_info_len", "network_info_len")
f.conversation_stats_ofs = ProtoField.bytes("microsoft_network_monitor_v2.conversation_stats_ofs", "conversation_stats_ofs")
f.conversation_stats_len = ProtoField.bytes("microsoft_network_monitor_v2.conversation_stats_len", "conversation_stats_len")
f.entries = ProtoField.bytes("microsoft_network_monitor_v2.frame_index.entries", "entries")
f.ofs = ProtoField.bytes("microsoft_network_monitor_v2.frame_index_entry.ofs", "ofs")
f.ts_delta = ProtoField.bytes("microsoft_network_monitor_v2.frame.ts_delta", "ts_delta")
f.orig_len = ProtoField.bytes("microsoft_network_monitor_v2.frame.orig_len", "orig_len")
f.inc_len = ProtoField.bytes("microsoft_network_monitor_v2.frame.inc_len", "inc_len")
f.body = ProtoField.bytes("microsoft_network_monitor_v2.frame.body", "body")

-- sub-type parsers
local function parse_frame_index(buffer, tree, offset)
  local subtree = tree:add("frame_index")
  -- entries: manual implementation needed (complex size/type)
  return offset
end

local function parse_frame_index_entry(buffer, tree, offset)
  local subtree = tree:add("frame_index_entry")
  local ofs_val = buffer(offset, 4):uint()
  subtree:add(f.ofs, buffer(offset, 4)); offset = offset + 4
  return offset
end

local function parse_frame(buffer, tree, offset)
  local subtree = tree:add("frame")
  -- ts_delta: manual implementation needed (complex size/type)
  local orig_len_val = buffer(offset, 4):uint()
  subtree:add(f.orig_len, buffer(offset, 4)); offset = offset + 4
  local inc_len_val = buffer(offset, 4):uint()
  subtree:add(f.inc_len, buffer(offset, 4)); offset = offset + 4
  local body_size = inc_len_val
  subtree:add(f.body, buffer(offset, body_size)); offset = offset + body_size
  return offset
end

-- main dissector
function microsoft_network_monitor_v2_proto.dissector(buffer, pinfo, tree)
  pinfo.cols.protocol = "microsoft_network_monitor_v2"
  local main = tree:add(microsoft_network_monitor_v2_proto, buffer(), "microsoft_network_monitor_v2")
  local offset = 0

  main:add(f.signature, buffer(offset, 4)); offset = offset + 4
  local version_minor_val = buffer(offset, 1):uint()
  main:add(f.version_minor, buffer(offset, 1)); offset = offset + 1
  local version_major_val = buffer(offset, 1):uint()
  main:add(f.version_major, buffer(offset, 1)); offset = offset + 1
  local mac_type_val = buffer(offset, 2):uint()
  main:add(f.mac_type, buffer(offset, 2)); offset = offset + 2
  -- time_capture_start: manual implementation needed (complex size/type)
  local frame_table_ofs_val = buffer(offset, 4):uint()
  main:add(f.frame_table_ofs, buffer(offset, 4)); offset = offset + 4
  local frame_table_len_val = buffer(offset, 4):uint()
  main:add(f.frame_table_len, buffer(offset, 4)); offset = offset + 4
  local user_data_ofs_val = buffer(offset, 4):uint()
  main:add(f.user_data_ofs, buffer(offset, 4)); offset = offset + 4
  local user_data_len_val = buffer(offset, 4):uint()
  main:add(f.user_data_len, buffer(offset, 4)); offset = offset + 4
  local comment_ofs_val = buffer(offset, 4):uint()
  main:add(f.comment_ofs, buffer(offset, 4)); offset = offset + 4
  local comment_len_val = buffer(offset, 4):uint()
  main:add(f.comment_len, buffer(offset, 4)); offset = offset + 4
  local statistics_ofs_val = buffer(offset, 4):uint()
  main:add(f.statistics_ofs, buffer(offset, 4)); offset = offset + 4
  local statistics_len_val = buffer(offset, 4):uint()
  main:add(f.statistics_len, buffer(offset, 4)); offset = offset + 4
  local network_info_ofs_val = buffer(offset, 4):uint()
  main:add(f.network_info_ofs, buffer(offset, 4)); offset = offset + 4
  local network_info_len_val = buffer(offset, 4):uint()
  main:add(f.network_info_len, buffer(offset, 4)); offset = offset + 4
  local conversation_stats_ofs_val = buffer(offset, 4):uint()
  main:add(f.conversation_stats_ofs, buffer(offset, 4)); offset = offset + 4
  local conversation_stats_len_val = buffer(offset, 4):uint()
  main:add(f.conversation_stats_len, buffer(offset, 4)); offset = offset + 4
end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(0, microsoft_network_monitor_v2_proto)
