rtp_packet_proto = Proto("kaitai_rtp_packet","rtp_packet file")

local f = rtp_packet_proto.fields

-- field declarations
f.version = ProtoField.bytes("kaitai_rtp_packet.version", "version")
f.has_padding = ProtoField.bytes("kaitai_rtp_packet.has_padding", "has_padding")
f.has_extension = ProtoField.bytes("kaitai_rtp_packet.has_extension", "has_extension")
f.csrc_count = ProtoField.bytes("kaitai_rtp_packet.csrc_count", "csrc_count")
f.marker = ProtoField.bytes("kaitai_rtp_packet.marker", "marker")
f.payload_type = ProtoField.bytes("kaitai_rtp_packet.payload_type", "payload_type")
f.sequence_number = ProtoField.bytes("kaitai_rtp_packet.sequence_number", "sequence_number")
f.timestamp = ProtoField.bytes("kaitai_rtp_packet.timestamp", "timestamp")
f.ssrc = ProtoField.bytes("kaitai_rtp_packet.ssrc", "ssrc")
f.header_extension = ProtoField.bytes("kaitai_rtp_packet.header_extension", "header_extension")
f.data = ProtoField.bytes("kaitai_rtp_packet.data", "data")
f.padding = ProtoField.bytes("kaitai_rtp_packet.padding", "padding")
f.id = ProtoField.bytes("kaitai_rtp_packet.header_extention.id", "id")
f.length = ProtoField.bytes("kaitai_rtp_packet.header_extention.length", "length")

-- sub-type parsers
local function parse_header_extention(buffer, tree, offset)
  local subtree = tree:add("header_extention")
  local id_val = buffer(offset, 2):uint()
  subtree:add(f.id, buffer(offset, 2)); offset = offset + 2
  local length_val = buffer(offset, 2):uint()
  subtree:add(f.length, buffer(offset, 2)); offset = offset + 2
  return offset
end

-- main dissector
function rtp_packet_proto.dissector(buffer, pinfo, tree)
  pinfo.cols.protocol = "rtp_packet"
  local main = tree:add(rtp_packet_proto, buffer(), "rtp_packet")
  local offset = 0

  -- version: manual implementation needed (complex size/type)
  -- has_padding: manual implementation needed (complex size/type)
  -- has_extension: manual implementation needed (complex size/type)
  -- csrc_count: manual implementation needed (complex size/type)
  -- marker: manual implementation needed (complex size/type)
  -- payload_type: manual implementation needed (complex size/type)
  local sequence_number_val = buffer(offset, 2):uint()
  main:add(f.sequence_number, buffer(offset, 2)); offset = offset + 2
  local timestamp_val = buffer(offset, 4):uint()
  main:add(f.timestamp, buffer(offset, 4)); offset = offset + 4
  local ssrc_val = buffer(offset, 4):uint()
  main:add(f.ssrc, buffer(offset, 4)); offset = offset + 4
  offset = parse_header_extention(buffer, main, offset)
  -- data: manual implementation needed (complex size/type)
  -- padding: manual implementation needed (complex size/type)
end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(0, rtp_packet_proto)
