ipv4_packet_proto = Proto("kaitai_ipv4_packet","ipv4_packet file")

local f = ipv4_packet_proto.fields

-- field declarations
f.b1 = ProtoField.bytes("kaitai_ipv4_packet.b1", "b1")
f.b2 = ProtoField.bytes("kaitai_ipv4_packet.b2", "b2")
f.total_length = ProtoField.bytes("kaitai_ipv4_packet.total_length", "total_length")
f.identification = ProtoField.bytes("kaitai_ipv4_packet.identification", "identification")
f.b67 = ProtoField.bytes("kaitai_ipv4_packet.b67", "b67")
f.ttl = ProtoField.bytes("kaitai_ipv4_packet.ttl", "ttl")
f.protocol = ProtoField.bytes("kaitai_ipv4_packet.protocol", "protocol")
f.header_checksum = ProtoField.bytes("kaitai_ipv4_packet.header_checksum", "header_checksum")
f.src_ip_addr = ProtoField.bytes("kaitai_ipv4_packet.src_ip_addr", "src_ip_addr")
f.dst_ip_addr = ProtoField.bytes("kaitai_ipv4_packet.dst_ip_addr", "dst_ip_addr")
f.options = ProtoField.bytes("kaitai_ipv4_packet.options", "options")
f.body = ProtoField.bytes("kaitai_ipv4_packet.body", "body")
f.entries = ProtoField.bytes("kaitai_ipv4_packet.ipv4_options.entries", "entries")
f.b1 = ProtoField.bytes("kaitai_ipv4_packet.ipv4_option.b1", "b1")
f.len = ProtoField.bytes("kaitai_ipv4_packet.ipv4_option.len", "len")
f.body = ProtoField.bytes("kaitai_ipv4_packet.ipv4_option.body", "body")

-- sub-type parsers
local function parse_ipv4_options(buffer, tree, offset)
  local subtree = tree:add("ipv4_options")
  -- entries: manual implementation needed (complex size/type)
  return offset
end

local function parse_ipv4_option(buffer, tree, offset)
  local subtree = tree:add("ipv4_option")
  local b1_val = buffer(offset, 1):uint()
  subtree:add(f.b1, buffer(offset, 1)); offset = offset + 1
  local len_val = buffer(offset, 1):uint()
  subtree:add(f.len, buffer(offset, 1)); offset = offset + 1
  -- body: manual implementation needed (complex size/type)
  return offset
end

-- main dissector
function ipv4_packet_proto.dissector(buffer, pinfo, tree)
  pinfo.cols.protocol = "ipv4_packet"
  local main = tree:add(ipv4_packet_proto, buffer(), "ipv4_packet")
  local offset = 0

  local b1_val = buffer(offset, 1):uint()
  main:add(f.b1, buffer(offset, 1)); offset = offset + 1
  local b2_val = buffer(offset, 1):uint()
  main:add(f.b2, buffer(offset, 1)); offset = offset + 1
  local total_length_val = buffer(offset, 2):uint()
  main:add(f.total_length, buffer(offset, 2)); offset = offset + 2
  local identification_val = buffer(offset, 2):uint()
  main:add(f.identification, buffer(offset, 2)); offset = offset + 2
  local b67_val = buffer(offset, 2):uint()
  main:add(f.b67, buffer(offset, 2)); offset = offset + 2
  local ttl_val = buffer(offset, 1):uint()
  main:add(f.ttl, buffer(offset, 1)); offset = offset + 1
  local protocol_val = buffer(offset, 1):uint()
  main:add(f.protocol, buffer(offset, 1)); offset = offset + 1
  local header_checksum_val = buffer(offset, 2):uint()
  main:add(f.header_checksum, buffer(offset, 2)); offset = offset + 2
  main:add(f.src_ip_addr, buffer(offset, 4)); offset = offset + 4
  main:add(f.dst_ip_addr, buffer(offset, 4)); offset = offset + 4
  offset = parse_ipv4_options(buffer, main, offset)
  -- body: manual implementation needed (complex size/type)
end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(0, ipv4_packet_proto)
