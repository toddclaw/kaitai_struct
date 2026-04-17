pcap_proto = Proto("kaitai_pcap","pcap file")

local f = pcap_proto.fields

-- field declarations
f.hdr = ProtoField.bytes("kaitai_pcap.hdr", "hdr")
f.packets = ProtoField.bytes("kaitai_pcap.packets", "packets")
f.magic_number = ProtoField.bytes("kaitai_pcap.header.magic_number", "magic_number")
f.version_major = ProtoField.bytes("kaitai_pcap.header.version_major", "version_major")
f.version_minor = ProtoField.bytes("kaitai_pcap.header.version_minor", "version_minor")
f.thiszone = ProtoField.bytes("kaitai_pcap.header.thiszone", "thiszone")
f.sigfigs = ProtoField.bytes("kaitai_pcap.header.sigfigs", "sigfigs")
f.snaplen = ProtoField.bytes("kaitai_pcap.header.snaplen", "snaplen")
f.network = ProtoField.bytes("kaitai_pcap.header.network", "network")
f.ts_sec = ProtoField.bytes("kaitai_pcap.packet.ts_sec", "ts_sec")
f.ts_usec = ProtoField.bytes("kaitai_pcap.packet.ts_usec", "ts_usec")
f.incl_len = ProtoField.bytes("kaitai_pcap.packet.incl_len", "incl_len")
f.orig_len = ProtoField.bytes("kaitai_pcap.packet.orig_len", "orig_len")
f.body = ProtoField.bytes("kaitai_pcap.packet.body", "body")

-- sub-type parsers
local function parse_header(buffer, tree, offset)
  local subtree = tree:add("header")
  subtree:add(f.magic_number, buffer(offset, 4)); offset = offset + 4
  local version_major_val = buffer(offset, 2):uint()
  subtree:add(f.version_major, buffer(offset, 2)); offset = offset + 2
  local version_minor_val = buffer(offset, 2):uint()
  subtree:add(f.version_minor, buffer(offset, 2)); offset = offset + 2
  -- thiszone: manual implementation needed (complex size/type)
  local sigfigs_val = buffer(offset, 4):uint()
  subtree:add(f.sigfigs, buffer(offset, 4)); offset = offset + 4
  local snaplen_val = buffer(offset, 4):uint()
  subtree:add(f.snaplen, buffer(offset, 4)); offset = offset + 4
  local network_val = buffer(offset, 4):uint()
  subtree:add(f.network, buffer(offset, 4)); offset = offset + 4
  return offset
end

local function parse_packet(buffer, tree, offset)
  local subtree = tree:add("packet")
  local ts_sec_val = buffer(offset, 4):uint()
  subtree:add(f.ts_sec, buffer(offset, 4)); offset = offset + 4
  local ts_usec_val = buffer(offset, 4):uint()
  subtree:add(f.ts_usec, buffer(offset, 4)); offset = offset + 4
  local incl_len_val = buffer(offset, 4):uint()
  subtree:add(f.incl_len, buffer(offset, 4)); offset = offset + 4
  local orig_len_val = buffer(offset, 4):uint()
  subtree:add(f.orig_len, buffer(offset, 4)); offset = offset + 4
  -- body: manual implementation needed (complex size/type)
  return offset
end

-- main dissector
function pcap_proto.dissector(buffer, pinfo, tree)
  pinfo.cols.protocol = "pcap"
  local main = tree:add(pcap_proto, buffer(), "pcap")
  local offset = 0

  offset = parse_header(buffer, main, offset)
  offset = parse_packet(buffer, main, offset)
end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(0, pcap_proto)
