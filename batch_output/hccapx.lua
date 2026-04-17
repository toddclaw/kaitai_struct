hccapx_proto = Proto("hccapx","hccapx file")

local f = hccapx_proto.fields

-- field declarations
f.records = ProtoField.bytes("hccapx.records", "records")
f.magic = ProtoField.bytes("hccapx.hccapx_record.magic", "magic")
f.version = ProtoField.bytes("hccapx.hccapx_record.version", "version")
f.ignore_replay_counter = ProtoField.bytes("hccapx.hccapx_record.ignore_replay_counter", "ignore_replay_counter")
f.message_pair = ProtoField.bytes("hccapx.hccapx_record.message_pair", "message_pair")
f.len_essid = ProtoField.bytes("hccapx.hccapx_record.len_essid", "len_essid")
f.essid = ProtoField.bytes("hccapx.hccapx_record.essid", "essid")
f.padding1 = ProtoField.bytes("hccapx.hccapx_record.padding1", "padding1")
f.keyver = ProtoField.bytes("hccapx.hccapx_record.keyver", "keyver")
f.keymic = ProtoField.bytes("hccapx.hccapx_record.keymic", "keymic")
f.mac_ap = ProtoField.bytes("hccapx.hccapx_record.mac_ap", "mac_ap")
f.nonce_ap = ProtoField.bytes("hccapx.hccapx_record.nonce_ap", "nonce_ap")
f.mac_station = ProtoField.bytes("hccapx.hccapx_record.mac_station", "mac_station")
f.nonce_station = ProtoField.bytes("hccapx.hccapx_record.nonce_station", "nonce_station")
f.len_eapol = ProtoField.bytes("hccapx.hccapx_record.len_eapol", "len_eapol")
f.eapol = ProtoField.bytes("hccapx.hccapx_record.eapol", "eapol")
f.padding2 = ProtoField.bytes("hccapx.hccapx_record.padding2", "padding2")

-- sub-type parsers
local function parse_hccapx_record(buffer, tree, offset)
  local sub = tree:add("hccapx_record")
  sub:add(f.magic, buffer(offset, 4)); offset = offset + 4
  local version_val = buffer(offset, 4):uint()
  sub:add(f.version, buffer(offset, 4)); offset = offset + 4
  -- ignore_replay_counter: manual implementation needed
  -- message_pair: manual implementation needed
  local len_essid_val = buffer(offset, 1):uint()
  sub:add(f.len_essid, buffer(offset, 1)); offset = offset + 1
  local essid_size = len_essid_val
  sub:add(f.essid, buffer(offset, essid_size)); offset = offset + essid_size
  local padding1_size = 32 - len_essid_val
  sub:add(f.padding1, buffer(offset, padding1_size)); offset = offset + padding1_size
  local keyver_val = buffer(offset, 1):uint()
  sub:add(f.keyver, buffer(offset, 1)); offset = offset + 1
  sub:add(f.keymic, buffer(offset, 16)); offset = offset + 16
  sub:add(f.mac_ap, buffer(offset, 6)); offset = offset + 6
  sub:add(f.nonce_ap, buffer(offset, 32)); offset = offset + 32
  sub:add(f.mac_station, buffer(offset, 6)); offset = offset + 6
  sub:add(f.nonce_station, buffer(offset, 32)); offset = offset + 32
  local len_eapol_val = buffer(offset, 2):uint()
  sub:add(f.len_eapol, buffer(offset, 2)); offset = offset + 2
  local eapol_size = len_eapol_val
  sub:add(f.eapol, buffer(offset, eapol_size)); offset = offset + eapol_size
  local padding2_size = 256 - len_eapol_val
  sub:add(f.padding2, buffer(offset, padding2_size)); offset = offset + padding2_size
  return offset
end

-- main dissector
function hccapx_proto.dissector(buffer, pinfo, tree)
  pinfo.cols.protocol = "hccapx"
  local main = tree:add(hccapx_proto, buffer(), "hccapx")
  local offset = 0

  offset = parse_hccapx_record(buffer, main, offset)
end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(0, hccapx_proto)
