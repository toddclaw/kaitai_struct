my_protocol_proto = Proto("kaitai_my_protocol","my_protocol file")

local f = my_protocol_proto.fields

-- field declarations
f.magic = ProtoField.bytes("my_protocol.magic", "magic")
f.version = ProtoField.bytes("my_protocol.version", "version")
f.msg_type = ProtoField.bytes("my_protocol.msg_type", "msg_type")
f.record_count = ProtoField.bytes("my_protocol.record_count", "record_count")
f.records = ProtoField.bytes("my_protocol.records", "records")
f.record_type = ProtoField.bytes("my_protocol.record.record_type", "record_type")
f.record_length = ProtoField.bytes("my_protocol.record.record_length", "record_length")
f.record_data = ProtoField.bytes("my_protocol.record.record_data", "record_data")

-- sub-type parsers
local function parse_record(buffer, tree, offset)
  local subtree = tree:add("record")
  local record_type_val = buffer(offset, 1):uint()
  subtree:add(f.record_type, buffer(offset, 1)); offset = offset + 1
  local record_length_val = buffer(offset, 1):uint()
  subtree:add(f.record_length, buffer(offset, 1)); offset = offset + 1
  local record_data_size = record_length_val
  subtree:add(f.record_data, buffer(offset, record_data_size)); offset = offset + record_data_size
  return offset
end

-- main dissector
function my_protocol_proto.dissector(buffer, pinfo, tree)
  pinfo.cols.protocol = "my_protocol"
  local main = tree:add(my_protocol_proto, buffer(), "my_protocol")
  local offset = 0

  main:add(f.magic, buffer(offset, 2)); offset = offset + 2
  local version_val = buffer(offset, 1):uint()
  main:add(f.version, buffer(offset, 1)); offset = offset + 1
  local msg_type_val = buffer(offset, 1):uint()
  main:add(f.msg_type, buffer(offset, 1)); offset = offset + 1
  local record_count_val = buffer(offset, 2):uint()
  main:add(f.record_count, buffer(offset, 2)); offset = offset + 2
  for _i = 1, record_count_val do
    offset = parse_record(buffer, main, offset)
  end
end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(8001, my_protocol_proto)
