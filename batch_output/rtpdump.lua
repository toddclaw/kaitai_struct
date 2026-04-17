rtpdump_proto = Proto("kaitai_rtpdump","rtpdump file")

local f = rtpdump_proto.fields

-- field declarations
f.file_header = ProtoField.bytes("kaitai_rtpdump.file_header", "file_header")
f.packets = ProtoField.bytes("kaitai_rtpdump.packets", "packets")
f.shebang = ProtoField.bytes("kaitai_rtpdump.header_t.shebang", "shebang")
f.space = ProtoField.bytes("kaitai_rtpdump.header_t.space", "space")
f.ip = ProtoField.bytes("kaitai_rtpdump.header_t.ip", "ip")
f.port = ProtoField.bytes("kaitai_rtpdump.header_t.port", "port")
f.start_sec = ProtoField.bytes("kaitai_rtpdump.header_t.start_sec", "start_sec")
f.start_usec = ProtoField.bytes("kaitai_rtpdump.header_t.start_usec", "start_usec")
f.ip2 = ProtoField.bytes("kaitai_rtpdump.header_t.ip2", "ip2")
f.port2 = ProtoField.bytes("kaitai_rtpdump.header_t.port2", "port2")
f.padding = ProtoField.bytes("kaitai_rtpdump.header_t.padding", "padding")
f.length = ProtoField.bytes("kaitai_rtpdump.packet_t.length", "length")
f.len_body = ProtoField.bytes("kaitai_rtpdump.packet_t.len_body", "len_body")
f.packet_usec = ProtoField.bytes("kaitai_rtpdump.packet_t.packet_usec", "packet_usec")
f.body = ProtoField.bytes("kaitai_rtpdump.packet_t.body", "body")

-- sub-type parsers
local function parse_header_t(buffer, tree, offset)
  local subtree = tree:add("header_t")
  subtree:add(f.shebang, buffer(offset, 12)); offset = offset + 12
  subtree:add(f.space, buffer(offset, 1)); offset = offset + 1
  -- ip: manual implementation needed (complex size/type)
  -- port: manual implementation needed (complex size/type)
  local start_sec_val = buffer(offset, 4):uint()
  subtree:add(f.start_sec, buffer(offset, 4)); offset = offset + 4
  local start_usec_val = buffer(offset, 4):uint()
  subtree:add(f.start_usec, buffer(offset, 4)); offset = offset + 4
  local ip2_val = buffer(offset, 4):uint()
  subtree:add(f.ip2, buffer(offset, 4)); offset = offset + 4
  local port2_val = buffer(offset, 2):uint()
  subtree:add(f.port2, buffer(offset, 2)); offset = offset + 2
  local padding_val = buffer(offset, 2):uint()
  subtree:add(f.padding, buffer(offset, 2)); offset = offset + 2
  return offset
end

local function parse_packet_t(buffer, tree, offset)
  local subtree = tree:add("packet_t")
  local length_val = buffer(offset, 2):uint()
  subtree:add(f.length, buffer(offset, 2)); offset = offset + 2
  local len_body_val = buffer(offset, 2):uint()
  subtree:add(f.len_body, buffer(offset, 2)); offset = offset + 2
  local packet_usec_val = buffer(offset, 4):uint()
  subtree:add(f.packet_usec, buffer(offset, 4)); offset = offset + 4
  local body_size = len_body_val
  subtree:add(f.body, buffer(offset, body_size)); offset = offset + body_size
  return offset
end

-- main dissector
function rtpdump_proto.dissector(buffer, pinfo, tree)
  pinfo.cols.protocol = "rtpdump"
  local main = tree:add(rtpdump_proto, buffer(), "rtpdump")
  local offset = 0

  offset = parse_header_t(buffer, main, offset)
  offset = parse_packet_t(buffer, main, offset)
end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(0, rtpdump_proto)
