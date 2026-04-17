pcap_proto = Proto("pcap","pcap file")

local f = pcap_proto.fields

-- field declarations
f.hdr = ProtoField.bytes("pcap.hdr", "hdr")
f.packets = ProtoField.bytes("pcap.packets", "packets")
f.magic_number = ProtoField.bytes("pcap.header.magic_number", "magic_number")
f.version_major = ProtoField.bytes("pcap.header.version_major", "version_major")
f.version_minor = ProtoField.bytes("pcap.header.version_minor", "version_minor")
f.thiszone = ProtoField.bytes("pcap.header.thiszone", "thiszone")
f.sigfigs = ProtoField.bytes("pcap.header.sigfigs", "sigfigs")
f.snaplen = ProtoField.bytes("pcap.header.snaplen", "snaplen")
f.network = ProtoField.bytes("pcap.header.network", "network")
f.ts_sec = ProtoField.bytes("pcap.packet.ts_sec", "ts_sec")
f.ts_usec = ProtoField.bytes("pcap.packet.ts_usec", "ts_usec")
f.incl_len = ProtoField.bytes("pcap.packet.incl_len", "incl_len")
f.orig_len = ProtoField.bytes("pcap.packet.orig_len", "orig_len")
f.body = ProtoField.bytes("pcap.packet.body", "body")

-- sub-type parsers
local function parse_header(buffer, tree, offset)
  local sub = tree:add("header")
  sub:add(f.magic_number, buffer(offset, 4)); offset = offset + 4
  local version_major_val = buffer(offset, 2):uint()
  sub:add(f.version_major, buffer(offset, 2)); offset = offset + 2
  local version_minor_val = buffer(offset, 2):uint()
  sub:add(f.version_minor, buffer(offset, 2)); offset = offset + 2
  -- thiszone: manual implementation needed
  local sigfigs_val = buffer(offset, 4):uint()
  sub:add(f.sigfigs, buffer(offset, 4)); offset = offset + 4
  local snaplen_val = buffer(offset, 4):uint()
  sub:add(f.snaplen, buffer(offset, 4)); offset = offset + 4
  local network_val = buffer(offset, 4):uint()
  sub:add(f.network, buffer(offset, 4)); offset = offset + 4
  return offset
end

local function parse_packet(buffer, tree, offset)
  local sub = tree:add("packet")
  local ts_sec_val = buffer(offset, 4):uint()
  sub:add(f.ts_sec, buffer(offset, 4)); offset = offset + 4
  local ts_usec_val = buffer(offset, 4):uint()
  sub:add(f.ts_usec, buffer(offset, 4)); offset = offset + 4
  local incl_len_val = buffer(offset, 4):uint()
  sub:add(f.incl_len, buffer(offset, 4)); offset = offset + 4
  local orig_len_val = buffer(offset, 4):uint()
  sub:add(f.orig_len, buffer(offset, 4)); offset = offset + 4
  local body_size = incl_len < _root.hdr.snaplen ? incl_len : _root.hdr.snaplen_val
  sub:add(f.body, buffer(offset, body_size)); offset = offset + body_size
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
