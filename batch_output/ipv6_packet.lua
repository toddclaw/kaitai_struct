ipv6_packet_proto = Proto("kaitai_ipv6_packet","ipv6_packet file")

local f = ipv6_packet_proto.fields

-- field declarations
f.version = ProtoField.bytes("kaitai_ipv6_packet.version", "version")
f.traffic_class = ProtoField.bytes("kaitai_ipv6_packet.traffic_class", "traffic_class")
f.flow_label = ProtoField.bytes("kaitai_ipv6_packet.flow_label", "flow_label")
f.payload_length = ProtoField.bytes("kaitai_ipv6_packet.payload_length", "payload_length")
f.next_header_type = ProtoField.bytes("kaitai_ipv6_packet.next_header_type", "next_header_type")
f.hop_limit = ProtoField.bytes("kaitai_ipv6_packet.hop_limit", "hop_limit")
f.src_ipv6_addr = ProtoField.bytes("kaitai_ipv6_packet.src_ipv6_addr", "src_ipv6_addr")
f.dst_ipv6_addr = ProtoField.bytes("kaitai_ipv6_packet.dst_ipv6_addr", "dst_ipv6_addr")
f.next_header = ProtoField.bytes("kaitai_ipv6_packet.next_header", "next_header")
f.rest = ProtoField.bytes("kaitai_ipv6_packet.rest", "rest")

-- sub-type parsers
-- main dissector
function ipv6_packet_proto.dissector(buffer, pinfo, tree)
  pinfo.cols.protocol = "ipv6_packet"
  local main = tree:add(ipv6_packet_proto, buffer(), "ipv6_packet")
  local offset = 0

  -- version: manual implementation needed (complex size/type)
  -- traffic_class: manual implementation needed (complex size/type)
  -- flow_label: manual implementation needed (complex size/type)
  local payload_length_val = buffer(offset, 2):uint()
  main:add(f.payload_length, buffer(offset, 2)); offset = offset + 2
  local next_header_type_val = buffer(offset, 1):uint()
  main:add(f.next_header_type, buffer(offset, 1)); offset = offset + 1
  local hop_limit_val = buffer(offset, 1):uint()
  main:add(f.hop_limit, buffer(offset, 1)); offset = offset + 1
  main:add(f.src_ipv6_addr, buffer(offset, 16)); offset = offset + 16
  main:add(f.dst_ipv6_addr, buffer(offset, 16)); offset = offset + 16
  -- next_header: manual implementation needed (complex size/type)
  -- rest: manual implementation needed (complex size/type)
end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(0, ipv6_packet_proto)
