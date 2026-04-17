rtcp_payload_proto = Proto("kaitai_rtcp_payload","rtcp_payload file")

local f = rtcp_payload_proto.fields

-- field declarations
f.rtcp_packets = ProtoField.bytes("kaitai_rtcp_payload.rtcp_packets", "rtcp_packets")
f.version = ProtoField.bytes("kaitai_rtcp_payload.rtcp_packet.version", "version")
f.padding = ProtoField.bytes("kaitai_rtcp_payload.rtcp_packet.padding", "padding")
f.subtype = ProtoField.bytes("kaitai_rtcp_payload.rtcp_packet.subtype", "subtype")
f.payload_type = ProtoField.bytes("kaitai_rtcp_payload.rtcp_packet.payload_type", "payload_type")
f.length = ProtoField.bytes("kaitai_rtcp_payload.rtcp_packet.length", "length")
f.body = ProtoField.bytes("kaitai_rtcp_payload.rtcp_packet.body", "body")
f.ssrc = ProtoField.bytes("kaitai_rtcp_payload.sr_packet.ssrc", "ssrc")
f.ntp_msw = ProtoField.bytes("kaitai_rtcp_payload.sr_packet.ntp_msw", "ntp_msw")
f.ntp_lsw = ProtoField.bytes("kaitai_rtcp_payload.sr_packet.ntp_lsw", "ntp_lsw")
f.rtp_timestamp = ProtoField.bytes("kaitai_rtcp_payload.sr_packet.rtp_timestamp", "rtp_timestamp")
f.sender_packet_count = ProtoField.bytes("kaitai_rtcp_payload.sr_packet.sender_packet_count", "sender_packet_count")
f.sender_octet_count = ProtoField.bytes("kaitai_rtcp_payload.sr_packet.sender_octet_count", "sender_octet_count")
f.report_block = ProtoField.bytes("kaitai_rtcp_payload.sr_packet.report_block", "report_block")
f.ssrc = ProtoField.bytes("kaitai_rtcp_payload.rr_packet.ssrc", "ssrc")
f.report_block = ProtoField.bytes("kaitai_rtcp_payload.rr_packet.report_block", "report_block")
f.ssrc_source = ProtoField.bytes("kaitai_rtcp_payload.report_block.ssrc_source", "ssrc_source")
f.lost_val = ProtoField.bytes("kaitai_rtcp_payload.report_block.lost_val", "lost_val")
f.highest_seq_num_received = ProtoField.bytes("kaitai_rtcp_payload.report_block.highest_seq_num_received", "highest_seq_num_received")
f.interarrival_jitter = ProtoField.bytes("kaitai_rtcp_payload.report_block.interarrival_jitter", "interarrival_jitter")
f.lsr = ProtoField.bytes("kaitai_rtcp_payload.report_block.lsr", "lsr")
f.dlsr = ProtoField.bytes("kaitai_rtcp_payload.report_block.dlsr", "dlsr")
f.source_chunk = ProtoField.bytes("kaitai_rtcp_payload.sdes_packet.source_chunk", "source_chunk")
f.ssrc = ProtoField.bytes("kaitai_rtcp_payload.source_chunk.ssrc", "ssrc")
f.sdes_tlv = ProtoField.bytes("kaitai_rtcp_payload.source_chunk.sdes_tlv", "sdes_tlv")
f.type = ProtoField.bytes("kaitai_rtcp_payload.sdes_tlv.type", "type")
f.length = ProtoField.bytes("kaitai_rtcp_payload.sdes_tlv.length", "length")
f.value = ProtoField.bytes("kaitai_rtcp_payload.sdes_tlv.value", "value")
f.ssrc = ProtoField.bytes("kaitai_rtcp_payload.rtpfb_packet.ssrc", "ssrc")
f.ssrc_media_source = ProtoField.bytes("kaitai_rtcp_payload.rtpfb_packet.ssrc_media_source", "ssrc_media_source")
f.fci_block = ProtoField.bytes("kaitai_rtcp_payload.rtpfb_packet.fci_block", "fci_block")
f.base_sequence_number = ProtoField.bytes("kaitai_rtcp_payload.rtpfb_transport_feedback_packet.base_sequence_number", "base_sequence_number")
f.packet_status_count = ProtoField.bytes("kaitai_rtcp_payload.rtpfb_transport_feedback_packet.packet_status_count", "packet_status_count")
f.b4 = ProtoField.bytes("kaitai_rtcp_payload.rtpfb_transport_feedback_packet.b4", "b4")
f.remaining = ProtoField.bytes("kaitai_rtcp_payload.rtpfb_transport_feedback_packet.remaining", "remaining")
f.t = ProtoField.bytes("kaitai_rtcp_payload.packet_status_chunk.t", "t")
f.s2 = ProtoField.bytes("kaitai_rtcp_payload.packet_status_chunk.s2", "s2")
f.s1 = ProtoField.bytes("kaitai_rtcp_payload.packet_status_chunk.s1", "s1")
f.rle = ProtoField.bytes("kaitai_rtcp_payload.packet_status_chunk.rle", "rle")
f.symbol_list = ProtoField.bytes("kaitai_rtcp_payload.packet_status_chunk.symbol_list", "symbol_list")
f.ssrc = ProtoField.bytes("kaitai_rtcp_payload.psfb_packet.ssrc", "ssrc")
f.ssrc_media_source = ProtoField.bytes("kaitai_rtcp_payload.psfb_packet.ssrc_media_source", "ssrc_media_source")
f.fci_block = ProtoField.bytes("kaitai_rtcp_payload.psfb_packet.fci_block", "fci_block")
f.uid = ProtoField.bytes("kaitai_rtcp_payload.psfb_afb_packet.uid", "uid")
f.contents = ProtoField.bytes("kaitai_rtcp_payload.psfb_afb_packet.contents", "contents")
f.num_ssrc = ProtoField.bytes("kaitai_rtcp_payload.psfb_afb_remb_packet.num_ssrc", "num_ssrc")
f.br_exp = ProtoField.bytes("kaitai_rtcp_payload.psfb_afb_remb_packet.br_exp", "br_exp")
f.br_mantissa = ProtoField.bytes("kaitai_rtcp_payload.psfb_afb_remb_packet.br_mantissa", "br_mantissa")
f.ssrc_list = ProtoField.bytes("kaitai_rtcp_payload.psfb_afb_remb_packet.ssrc_list", "ssrc_list")

-- sub-type parsers
local function parse_rtcp_packet(buffer, tree, offset)
  local subtree = tree:add("rtcp_packet")
  -- version: manual implementation needed (complex size/type)
  -- padding: manual implementation needed (complex size/type)
  -- subtype: manual implementation needed (complex size/type)
  local payload_type_val = buffer(offset, 1):uint()
  subtree:add(f.payload_type, buffer(offset, 1)); offset = offset + 1
  local length_val = buffer(offset, 2):uint()
  subtree:add(f.length, buffer(offset, 2)); offset = offset + 2
  -- body: manual implementation needed (complex size/type)
  return offset
end

local function parse_sr_packet(buffer, tree, offset)
  local subtree = tree:add("sr_packet")
  local ssrc_val = buffer(offset, 4):uint()
  subtree:add(f.ssrc, buffer(offset, 4)); offset = offset + 4
  local ntp_msw_val = buffer(offset, 4):uint()
  subtree:add(f.ntp_msw, buffer(offset, 4)); offset = offset + 4
  local ntp_lsw_val = buffer(offset, 4):uint()
  subtree:add(f.ntp_lsw, buffer(offset, 4)); offset = offset + 4
  local rtp_timestamp_val = buffer(offset, 4):uint()
  subtree:add(f.rtp_timestamp, buffer(offset, 4)); offset = offset + 4
  local sender_packet_count_val = buffer(offset, 4):uint()
  subtree:add(f.sender_packet_count, buffer(offset, 4)); offset = offset + 4
  local sender_octet_count_val = buffer(offset, 4):uint()
  subtree:add(f.sender_octet_count, buffer(offset, 4)); offset = offset + 4
  -- report_block: manual implementation needed (complex size/type)
  return offset
end

local function parse_rr_packet(buffer, tree, offset)
  local subtree = tree:add("rr_packet")
  local ssrc_val = buffer(offset, 4):uint()
  subtree:add(f.ssrc, buffer(offset, 4)); offset = offset + 4
  -- report_block: manual implementation needed (complex size/type)
  return offset
end

local function parse_report_block(buffer, tree, offset)
  local subtree = tree:add("report_block")
  local ssrc_source_val = buffer(offset, 4):uint()
  subtree:add(f.ssrc_source, buffer(offset, 4)); offset = offset + 4
  local lost_val_val = buffer(offset, 1):uint()
  subtree:add(f.lost_val, buffer(offset, 1)); offset = offset + 1
  local highest_seq_num_received_val = buffer(offset, 4):uint()
  subtree:add(f.highest_seq_num_received, buffer(offset, 4)); offset = offset + 4
  local interarrival_jitter_val = buffer(offset, 4):uint()
  subtree:add(f.interarrival_jitter, buffer(offset, 4)); offset = offset + 4
  local lsr_val = buffer(offset, 4):uint()
  subtree:add(f.lsr, buffer(offset, 4)); offset = offset + 4
  local dlsr_val = buffer(offset, 4):uint()
  subtree:add(f.dlsr, buffer(offset, 4)); offset = offset + 4
  return offset
end

local function parse_sdes_packet(buffer, tree, offset)
  local subtree = tree:add("sdes_packet")
  -- source_chunk: manual implementation needed (complex size/type)
  return offset
end

local function parse_source_chunk(buffer, tree, offset)
  local subtree = tree:add("source_chunk")
  local ssrc_val = buffer(offset, 4):uint()
  subtree:add(f.ssrc, buffer(offset, 4)); offset = offset + 4
  -- sdes_tlv: manual implementation needed (complex size/type)
  return offset
end

local function parse_sdes_tlv(buffer, tree, offset)
  local subtree = tree:add("sdes_tlv")
  local type_val = buffer(offset, 1):uint()
  subtree:add(f.type, buffer(offset, 1)); offset = offset + 1
  local length_val = buffer(offset, 1):uint()
  subtree:add(f.length, buffer(offset, 1)); offset = offset + 1
  local value_size = length_val
  subtree:add(f.value, buffer(offset, value_size)); offset = offset + value_size
  return offset
end

local function parse_rtpfb_packet(buffer, tree, offset)
  local subtree = tree:add("rtpfb_packet")
  local ssrc_val = buffer(offset, 4):uint()
  subtree:add(f.ssrc, buffer(offset, 4)); offset = offset + 4
  local ssrc_media_source_val = buffer(offset, 4):uint()
  subtree:add(f.ssrc_media_source, buffer(offset, 4)); offset = offset + 4
  -- fci_block: manual implementation needed (complex size/type)
  return offset
end

local function parse_rtpfb_transport_feedback_packet(buffer, tree, offset)
  local subtree = tree:add("rtpfb_transport_feedback_packet")
  local base_sequence_number_val = buffer(offset, 2):uint()
  subtree:add(f.base_sequence_number, buffer(offset, 2)); offset = offset + 2
  local packet_status_count_val = buffer(offset, 2):uint()
  subtree:add(f.packet_status_count, buffer(offset, 2)); offset = offset + 2
  local b4_val = buffer(offset, 4):uint()
  subtree:add(f.b4, buffer(offset, 4)); offset = offset + 4
  -- remaining: manual implementation needed (complex size/type)
  return offset
end

local function parse_packet_status_chunk(buffer, tree, offset)
  local subtree = tree:add("packet_status_chunk")
  -- t: manual implementation needed (complex size/type)
  -- s2: manual implementation needed (complex size/type)
  -- s1: manual implementation needed (complex size/type)
  -- rle: manual implementation needed (complex size/type)
  -- symbol_list: manual implementation needed (complex size/type)
  return offset
end

local function parse_psfb_packet(buffer, tree, offset)
  local subtree = tree:add("psfb_packet")
  local ssrc_val = buffer(offset, 4):uint()
  subtree:add(f.ssrc, buffer(offset, 4)); offset = offset + 4
  local ssrc_media_source_val = buffer(offset, 4):uint()
  subtree:add(f.ssrc_media_source, buffer(offset, 4)); offset = offset + 4
  -- fci_block: manual implementation needed (complex size/type)
  return offset
end

local function parse_psfb_afb_packet(buffer, tree, offset)
  local subtree = tree:add("psfb_afb_packet")
  local uid_val = buffer(offset, 4):uint()
  subtree:add(f.uid, buffer(offset, 4)); offset = offset + 4
  -- contents: manual implementation needed (complex size/type)
  return offset
end

local function parse_psfb_afb_remb_packet(buffer, tree, offset)
  local subtree = tree:add("psfb_afb_remb_packet")
  local num_ssrc_val = buffer(offset, 1):uint()
  subtree:add(f.num_ssrc, buffer(offset, 1)); offset = offset + 1
  -- br_exp: manual implementation needed (complex size/type)
  -- br_mantissa: manual implementation needed (complex size/type)
  local ssrc_list_val = buffer(offset, 4):uint()
  subtree:add(f.ssrc_list, buffer(offset, 4)); offset = offset + 4
  return offset
end

-- main dissector
function rtcp_payload_proto.dissector(buffer, pinfo, tree)
  pinfo.cols.protocol = "rtcp_payload"
  local main = tree:add(rtcp_payload_proto, buffer(), "rtcp_payload")
  local offset = 0

  offset = parse_rtcp_packet(buffer, main, offset)
end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(0, rtcp_payload_proto)
