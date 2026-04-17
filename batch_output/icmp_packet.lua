icmp_packet_proto = Proto("kaitai_icmp_packet","icmp_packet file")

local f = icmp_packet_proto.fields

-- field declarations
f.icmp_type = ProtoField.bytes("kaitai_icmp_packet.icmp_type", "icmp_type")
f.destination_unreachable = ProtoField.bytes("kaitai_icmp_packet.destination_unreachable", "destination_unreachable")
f.time_exceeded = ProtoField.bytes("kaitai_icmp_packet.time_exceeded", "time_exceeded")
f.echo = ProtoField.bytes("kaitai_icmp_packet.echo", "echo")
f.code = ProtoField.bytes("kaitai_icmp_packet.destination_unreachable_msg.code", "code")
f.checksum = ProtoField.bytes("kaitai_icmp_packet.destination_unreachable_msg.checksum", "checksum")
f.code = ProtoField.bytes("kaitai_icmp_packet.time_exceeded_msg.code", "code")
f.checksum = ProtoField.bytes("kaitai_icmp_packet.time_exceeded_msg.checksum", "checksum")
f.code = ProtoField.bytes("kaitai_icmp_packet.echo_msg.code", "code")
f.checksum = ProtoField.bytes("kaitai_icmp_packet.echo_msg.checksum", "checksum")
f.identifier = ProtoField.bytes("kaitai_icmp_packet.echo_msg.identifier", "identifier")
f.seq_num = ProtoField.bytes("kaitai_icmp_packet.echo_msg.seq_num", "seq_num")
f.data = ProtoField.bytes("kaitai_icmp_packet.echo_msg.data", "data")

-- sub-type parsers
local function parse_destination_unreachable_msg(buffer, tree, offset)
  local subtree = tree:add("destination_unreachable_msg")
  local code_val = buffer(offset, 1):uint()
  subtree:add(f.code, buffer(offset, 1)); offset = offset + 1
  local checksum_val = buffer(offset, 2):uint()
  subtree:add(f.checksum, buffer(offset, 2)); offset = offset + 2
  return offset
end

local function parse_time_exceeded_msg(buffer, tree, offset)
  local subtree = tree:add("time_exceeded_msg")
  local code_val = buffer(offset, 1):uint()
  subtree:add(f.code, buffer(offset, 1)); offset = offset + 1
  local checksum_val = buffer(offset, 2):uint()
  subtree:add(f.checksum, buffer(offset, 2)); offset = offset + 2
  return offset
end

local function parse_echo_msg(buffer, tree, offset)
  local subtree = tree:add("echo_msg")
  subtree:add(f.code, buffer(offset, 1)); offset = offset + 1
  local checksum_val = buffer(offset, 2):uint()
  subtree:add(f.checksum, buffer(offset, 2)); offset = offset + 2
  local identifier_val = buffer(offset, 2):uint()
  subtree:add(f.identifier, buffer(offset, 2)); offset = offset + 2
  local seq_num_val = buffer(offset, 2):uint()
  subtree:add(f.seq_num, buffer(offset, 2)); offset = offset + 2
  -- data: manual implementation needed (complex size/type)
  return offset
end

-- main dissector
function icmp_packet_proto.dissector(buffer, pinfo, tree)
  pinfo.cols.protocol = "icmp_packet"
  local main = tree:add(icmp_packet_proto, buffer(), "icmp_packet")
  local offset = 0

  local icmp_type_val = buffer(offset, 1):uint()
  main:add(f.icmp_type, buffer(offset, 1)); offset = offset + 1
  offset = parse_destination_unreachable_msg(buffer, main, offset)
  offset = parse_time_exceeded_msg(buffer, main, offset)
  offset = parse_echo_msg(buffer, main, offset)
end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(0, icmp_packet_proto)
