hccap_proto = Proto("hccap","hccap file")

local f = hccap_proto.fields

-- field declarations
f.records = ProtoField.bytes("hccap.records", "records")
f.essid = ProtoField.bytes("hccap.hccap_record.essid", "essid")
f.mac_ap = ProtoField.bytes("hccap.hccap_record.mac_ap", "mac_ap")
f.mac_station = ProtoField.bytes("hccap.hccap_record.mac_station", "mac_station")
f.nonce_station = ProtoField.bytes("hccap.hccap_record.nonce_station", "nonce_station")
f.nonce_ap = ProtoField.bytes("hccap.hccap_record.nonce_ap", "nonce_ap")
f.eapol_buffer = ProtoField.bytes("hccap.hccap_record.eapol_buffer", "eapol_buffer")
f.len_eapol = ProtoField.bytes("hccap.hccap_record.len_eapol", "len_eapol")
f.keyver = ProtoField.bytes("hccap.hccap_record.keyver", "keyver")
f.keymic = ProtoField.bytes("hccap.hccap_record.keymic", "keymic")

-- sub-type parsers
local function parse_hccap_record(buffer, tree, offset)
  local sub = tree:add("hccap_record")
  sub:add(f.essid, buffer(offset, 36)); offset = offset + 36
  sub:add(f.mac_ap, buffer(offset, 6)); offset = offset + 6
  sub:add(f.mac_station, buffer(offset, 6)); offset = offset + 6
  sub:add(f.nonce_station, buffer(offset, 32)); offset = offset + 32
  sub:add(f.nonce_ap, buffer(offset, 32)); offset = offset + 32
  sub:add(f.eapol_buffer, buffer(offset, 256)); offset = offset + 256
  local len_eapol_val = buffer(offset, 4):uint()
  sub:add(f.len_eapol, buffer(offset, 4)); offset = offset + 4
  local keyver_val = buffer(offset, 4):uint()
  sub:add(f.keyver, buffer(offset, 4)); offset = offset + 4
  sub:add(f.keymic, buffer(offset, 16)); offset = offset + 16
  return offset
end

local function parse_eapol_dummy(buffer, tree, offset)
  local sub = tree:add("eapol_dummy")
  return offset
end

-- main dissector
function hccap_proto.dissector(buffer, pinfo, tree)
  pinfo.cols.protocol = "hccap"
  local main = tree:add(hccap_proto, buffer(), "hccap")
  local offset = 0

  offset = parse_hccap_record(buffer, main, offset)
end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(0, hccap_proto)
