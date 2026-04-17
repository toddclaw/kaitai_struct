udp_datagram_proto = Proto("kaitai_udp_datagram","udp_datagram file")

local f = udp_datagram_proto.fields

-- field declarations
f.src_port = ProtoField.bytes("udp_datagram.src_port", "src_port")
f.dst_port = ProtoField.bytes("udp_datagram.dst_port", "dst_port")
f.length = ProtoField.bytes("udp_datagram.length", "length")
f.checksum = ProtoField.bytes("udp_datagram.checksum", "checksum")
f.body = ProtoField.bytes("udp_datagram.body", "body")

-- sub-type parsers
-- main dissector
function udp_datagram_proto.dissector(buffer, pinfo, tree)
  pinfo.cols.protocol = "udp_datagram"
  local main = tree:add(udp_datagram_proto, buffer(), "udp_datagram")
  local offset = 0

  local src_port_val = buffer(offset, 2):uint()
  main:add(f.src_port, buffer(offset, 2)); offset = offset + 2
  local dst_port_val = buffer(offset, 2):uint()
  main:add(f.dst_port, buffer(offset, 2)); offset = offset + 2
  local length_val = buffer(offset, 2):uint()
  main:add(f.length, buffer(offset, 2)); offset = offset + 2
  local checksum_val = buffer(offset, 2):uint()
  main:add(f.checksum, buffer(offset, 2)); offset = offset + 2
  -- body: manual implementation needed (complex size/type)
end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(0, udp_datagram_proto)
