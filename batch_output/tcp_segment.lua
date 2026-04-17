tcp_segment_proto = Proto("kaitai_tcp_segment","tcp_segment file")

local f = tcp_segment_proto.fields

-- field declarations
f.src_port = ProtoField.bytes("kaitai_tcp_segment.src_port", "src_port")
f.dst_port = ProtoField.bytes("kaitai_tcp_segment.dst_port", "dst_port")
f.seq_num = ProtoField.bytes("kaitai_tcp_segment.seq_num", "seq_num")
f.ack_num = ProtoField.bytes("kaitai_tcp_segment.ack_num", "ack_num")
f.data_offset = ProtoField.bytes("kaitai_tcp_segment.data_offset", "data_offset")
f.reserved = ProtoField.bytes("kaitai_tcp_segment.reserved", "reserved")
f.flags = ProtoField.bytes("kaitai_tcp_segment.flags", "flags")
f.window_size = ProtoField.bytes("kaitai_tcp_segment.window_size", "window_size")
f.checksum = ProtoField.bytes("kaitai_tcp_segment.checksum", "checksum")
f.urgent_pointer = ProtoField.bytes("kaitai_tcp_segment.urgent_pointer", "urgent_pointer")
f.options = ProtoField.bytes("kaitai_tcp_segment.options", "options")
f.body = ProtoField.bytes("kaitai_tcp_segment.body", "body")
f.cwr = ProtoField.bytes("kaitai_tcp_segment.flags.cwr", "cwr")
f.ece = ProtoField.bytes("kaitai_tcp_segment.flags.ece", "ece")
f.urg = ProtoField.bytes("kaitai_tcp_segment.flags.urg", "urg")
f.ack = ProtoField.bytes("kaitai_tcp_segment.flags.ack", "ack")
f.psh = ProtoField.bytes("kaitai_tcp_segment.flags.psh", "psh")
f.rst = ProtoField.bytes("kaitai_tcp_segment.flags.rst", "rst")
f.syn = ProtoField.bytes("kaitai_tcp_segment.flags.syn", "syn")
f.fin = ProtoField.bytes("kaitai_tcp_segment.flags.fin", "fin")

-- sub-type parsers
local function parse_flags(buffer, tree, offset)
  local subtree = tree:add("flags")
  -- cwr: manual implementation needed (complex size/type)
  -- ece: manual implementation needed (complex size/type)
  -- urg: manual implementation needed (complex size/type)
  -- ack: manual implementation needed (complex size/type)
  -- psh: manual implementation needed (complex size/type)
  -- rst: manual implementation needed (complex size/type)
  -- syn: manual implementation needed (complex size/type)
  -- fin: manual implementation needed (complex size/type)
  return offset
end

-- main dissector
function tcp_segment_proto.dissector(buffer, pinfo, tree)
  pinfo.cols.protocol = "tcp_segment"
  local main = tree:add(tcp_segment_proto, buffer(), "tcp_segment")
  local offset = 0

  local src_port_val = buffer(offset, 2):uint()
  main:add(f.src_port, buffer(offset, 2)); offset = offset + 2
  local dst_port_val = buffer(offset, 2):uint()
  main:add(f.dst_port, buffer(offset, 2)); offset = offset + 2
  local seq_num_val = buffer(offset, 4):uint()
  main:add(f.seq_num, buffer(offset, 4)); offset = offset + 4
  local ack_num_val = buffer(offset, 4):uint()
  main:add(f.ack_num, buffer(offset, 4)); offset = offset + 4
  -- data_offset: manual implementation needed (complex size/type)
  -- reserved: manual implementation needed (complex size/type)
  offset = parse_flags(buffer, main, offset)
  local window_size_val = buffer(offset, 2):uint()
  main:add(f.window_size, buffer(offset, 2)); offset = offset + 2
  local checksum_val = buffer(offset, 2):uint()
  main:add(f.checksum, buffer(offset, 2)); offset = offset + 2
  local urgent_pointer_val = buffer(offset, 2):uint()
  main:add(f.urgent_pointer, buffer(offset, 2)); offset = offset + 2
  -- options: manual implementation needed (complex size/type)
  -- body: manual implementation needed (complex size/type)
end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(0, tcp_segment_proto)
