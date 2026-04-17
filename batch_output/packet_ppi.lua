packet_ppi_proto = Proto("kaitai_packet_ppi","packet_ppi file")

local f = packet_ppi_proto.fields

-- field declarations
f.header = ProtoField.bytes("kaitai_packet_ppi.header", "header")
f.fields = ProtoField.bytes("kaitai_packet_ppi.fields", "fields")
f.body = ProtoField.bytes("kaitai_packet_ppi.body", "body")
f.pph_version = ProtoField.bytes("kaitai_packet_ppi.packet_ppi_header.pph_version", "pph_version")
f.pph_flags = ProtoField.bytes("kaitai_packet_ppi.packet_ppi_header.pph_flags", "pph_flags")
f.pph_len = ProtoField.bytes("kaitai_packet_ppi.packet_ppi_header.pph_len", "pph_len")
f.pph_dlt = ProtoField.bytes("kaitai_packet_ppi.packet_ppi_header.pph_dlt", "pph_dlt")
f.entries = ProtoField.bytes("kaitai_packet_ppi.packet_ppi_fields.entries", "entries")
f.pfh_type = ProtoField.bytes("kaitai_packet_ppi.packet_ppi_field.pfh_type", "pfh_type")
f.pfh_datalen = ProtoField.bytes("kaitai_packet_ppi.packet_ppi_field.pfh_datalen", "pfh_datalen")
f.body = ProtoField.bytes("kaitai_packet_ppi.packet_ppi_field.body", "body")
f.tsf_timer = ProtoField.bytes("kaitai_packet_ppi.radio_802_11_common_body.tsf_timer", "tsf_timer")
f.flags = ProtoField.bytes("kaitai_packet_ppi.radio_802_11_common_body.flags", "flags")
f.rate = ProtoField.bytes("kaitai_packet_ppi.radio_802_11_common_body.rate", "rate")
f.channel_freq = ProtoField.bytes("kaitai_packet_ppi.radio_802_11_common_body.channel_freq", "channel_freq")
f.channel_flags = ProtoField.bytes("kaitai_packet_ppi.radio_802_11_common_body.channel_flags", "channel_flags")
f.fhss_hopset = ProtoField.bytes("kaitai_packet_ppi.radio_802_11_common_body.fhss_hopset", "fhss_hopset")
f.fhss_pattern = ProtoField.bytes("kaitai_packet_ppi.radio_802_11_common_body.fhss_pattern", "fhss_pattern")
f.dbm_antsignal = ProtoField.bytes("kaitai_packet_ppi.radio_802_11_common_body.dbm_antsignal", "dbm_antsignal")
f.dbm_antnoise = ProtoField.bytes("kaitai_packet_ppi.radio_802_11_common_body.dbm_antnoise", "dbm_antnoise")
f.flags = ProtoField.bytes("kaitai_packet_ppi.radio_802_11n_mac_ext_body.flags", "flags")
f.a_mpdu_id = ProtoField.bytes("kaitai_packet_ppi.radio_802_11n_mac_ext_body.a_mpdu_id", "a_mpdu_id")
f.num_delimiters = ProtoField.bytes("kaitai_packet_ppi.radio_802_11n_mac_ext_body.num_delimiters", "num_delimiters")
f.reserved = ProtoField.bytes("kaitai_packet_ppi.radio_802_11n_mac_ext_body.reserved", "reserved")
f.flags = ProtoField.bytes("kaitai_packet_ppi.radio_802_11n_mac_phy_ext_body.flags", "flags")
f.a_mpdu_id = ProtoField.bytes("kaitai_packet_ppi.radio_802_11n_mac_phy_ext_body.a_mpdu_id", "a_mpdu_id")
f.num_delimiters = ProtoField.bytes("kaitai_packet_ppi.radio_802_11n_mac_phy_ext_body.num_delimiters", "num_delimiters")
f.mcs = ProtoField.bytes("kaitai_packet_ppi.radio_802_11n_mac_phy_ext_body.mcs", "mcs")
f.num_streams = ProtoField.bytes("kaitai_packet_ppi.radio_802_11n_mac_phy_ext_body.num_streams", "num_streams")
f.rssi_combined = ProtoField.bytes("kaitai_packet_ppi.radio_802_11n_mac_phy_ext_body.rssi_combined", "rssi_combined")
f.rssi_ant_ctl = ProtoField.bytes("kaitai_packet_ppi.radio_802_11n_mac_phy_ext_body.rssi_ant_ctl", "rssi_ant_ctl")
f.rssi_ant_ext = ProtoField.bytes("kaitai_packet_ppi.radio_802_11n_mac_phy_ext_body.rssi_ant_ext", "rssi_ant_ext")
f.ext_channel_freq = ProtoField.bytes("kaitai_packet_ppi.radio_802_11n_mac_phy_ext_body.ext_channel_freq", "ext_channel_freq")
f.ext_channel_flags = ProtoField.bytes("kaitai_packet_ppi.radio_802_11n_mac_phy_ext_body.ext_channel_flags", "ext_channel_flags")
f.rf_signal_noise = ProtoField.bytes("kaitai_packet_ppi.radio_802_11n_mac_phy_ext_body.rf_signal_noise", "rf_signal_noise")
f.evm = ProtoField.bytes("kaitai_packet_ppi.radio_802_11n_mac_phy_ext_body.evm", "evm")
f.unused1 = ProtoField.bytes("kaitai_packet_ppi.mac_flags.unused1", "unused1")
f.aggregate_delimiter = ProtoField.bytes("kaitai_packet_ppi.mac_flags.aggregate_delimiter", "aggregate_delimiter")
f.more_aggregates = ProtoField.bytes("kaitai_packet_ppi.mac_flags.more_aggregates", "more_aggregates")
f.aggregate = ProtoField.bytes("kaitai_packet_ppi.mac_flags.aggregate", "aggregate")
f.dup_rx = ProtoField.bytes("kaitai_packet_ppi.mac_flags.dup_rx", "dup_rx")
f.rx_short_guard = ProtoField.bytes("kaitai_packet_ppi.mac_flags.rx_short_guard", "rx_short_guard")
f.is_ht_40 = ProtoField.bytes("kaitai_packet_ppi.mac_flags.is_ht_40", "is_ht_40")
f.greenfield = ProtoField.bytes("kaitai_packet_ppi.mac_flags.greenfield", "greenfield")
f.unused2 = ProtoField.bytes("kaitai_packet_ppi.mac_flags.unused2", "unused2")

-- sub-type parsers
local function parse_packet_ppi_header(buffer, tree, offset)
  local subtree = tree:add("packet_ppi_header")
  local pph_version_val = buffer(offset, 1):uint()
  subtree:add(f.pph_version, buffer(offset, 1)); offset = offset + 1
  local pph_flags_val = buffer(offset, 1):uint()
  subtree:add(f.pph_flags, buffer(offset, 1)); offset = offset + 1
  local pph_len_val = buffer(offset, 2):uint()
  subtree:add(f.pph_len, buffer(offset, 2)); offset = offset + 2
  local pph_dlt_val = buffer(offset, 4):uint()
  subtree:add(f.pph_dlt, buffer(offset, 4)); offset = offset + 4
  return offset
end

local function parse_packet_ppi_fields(buffer, tree, offset)
  local subtree = tree:add("packet_ppi_fields")
  -- entries: manual implementation needed (complex size/type)
  return offset
end

local function parse_packet_ppi_field(buffer, tree, offset)
  local subtree = tree:add("packet_ppi_field")
  local pfh_type_val = buffer(offset, 2):uint()
  subtree:add(f.pfh_type, buffer(offset, 2)); offset = offset + 2
  local pfh_datalen_val = buffer(offset, 2):uint()
  subtree:add(f.pfh_datalen, buffer(offset, 2)); offset = offset + 2
  local body_size = pfh_datalen_val
  subtree:add(f.body, buffer(offset, body_size)); offset = offset + body_size
  return offset
end

local function parse_radio_802_11_common_body(buffer, tree, offset)
  local subtree = tree:add("radio_802_11_common_body")
  -- tsf_timer: manual implementation needed (complex size/type)
  local flags_val = buffer(offset, 2):uint()
  subtree:add(f.flags, buffer(offset, 2)); offset = offset + 2
  local rate_val = buffer(offset, 2):uint()
  subtree:add(f.rate, buffer(offset, 2)); offset = offset + 2
  local channel_freq_val = buffer(offset, 2):uint()
  subtree:add(f.channel_freq, buffer(offset, 2)); offset = offset + 2
  local channel_flags_val = buffer(offset, 2):uint()
  subtree:add(f.channel_flags, buffer(offset, 2)); offset = offset + 2
  local fhss_hopset_val = buffer(offset, 1):uint()
  subtree:add(f.fhss_hopset, buffer(offset, 1)); offset = offset + 1
  local fhss_pattern_val = buffer(offset, 1):uint()
  subtree:add(f.fhss_pattern, buffer(offset, 1)); offset = offset + 1
  -- dbm_antsignal: manual implementation needed (complex size/type)
  -- dbm_antnoise: manual implementation needed (complex size/type)
  return offset
end

local function parse_radio_802_11n_mac_ext_body(buffer, tree, offset)
  local subtree = tree:add("radio_802_11n_mac_ext_body")
  -- flags: manual implementation needed (complex size/type)
  local a_mpdu_id_val = buffer(offset, 4):uint()
  subtree:add(f.a_mpdu_id, buffer(offset, 4)); offset = offset + 4
  local num_delimiters_val = buffer(offset, 1):uint()
  subtree:add(f.num_delimiters, buffer(offset, 1)); offset = offset + 1
  subtree:add(f.reserved, buffer(offset, 3)); offset = offset + 3
  return offset
end

local function parse_radio_802_11n_mac_phy_ext_body(buffer, tree, offset)
  local subtree = tree:add("radio_802_11n_mac_phy_ext_body")
  -- flags: manual implementation needed (complex size/type)
  local a_mpdu_id_val = buffer(offset, 4):uint()
  subtree:add(f.a_mpdu_id, buffer(offset, 4)); offset = offset + 4
  local num_delimiters_val = buffer(offset, 1):uint()
  subtree:add(f.num_delimiters, buffer(offset, 1)); offset = offset + 1
  local mcs_val = buffer(offset, 1):uint()
  subtree:add(f.mcs, buffer(offset, 1)); offset = offset + 1
  local num_streams_val = buffer(offset, 1):uint()
  subtree:add(f.num_streams, buffer(offset, 1)); offset = offset + 1
  local rssi_combined_val = buffer(offset, 1):uint()
  subtree:add(f.rssi_combined, buffer(offset, 1)); offset = offset + 1
  local rssi_ant_ctl_val = buffer(offset, 1):uint()
  subtree:add(f.rssi_ant_ctl, buffer(offset, 1)); offset = offset + 1
  local rssi_ant_ext_val = buffer(offset, 1):uint()
  subtree:add(f.rssi_ant_ext, buffer(offset, 1)); offset = offset + 1
  local ext_channel_freq_val = buffer(offset, 2):uint()
  subtree:add(f.ext_channel_freq, buffer(offset, 2)); offset = offset + 2
  -- ext_channel_flags: manual implementation needed (complex size/type)
  -- rf_signal_noise: manual implementation needed (complex size/type)
  local evm_val = buffer(offset, 4):uint()
  subtree:add(f.evm, buffer(offset, 4)); offset = offset + 4
  return offset
end

local function parse_mac_flags(buffer, tree, offset)
  local subtree = tree:add("mac_flags")
  -- unused1: manual implementation needed (complex size/type)
  -- aggregate_delimiter: manual implementation needed (complex size/type)
  -- more_aggregates: manual implementation needed (complex size/type)
  -- aggregate: manual implementation needed (complex size/type)
  -- dup_rx: manual implementation needed (complex size/type)
  -- rx_short_guard: manual implementation needed (complex size/type)
  -- is_ht_40: manual implementation needed (complex size/type)
  -- greenfield: manual implementation needed (complex size/type)
  subtree:add(f.unused2, buffer(offset, 3)); offset = offset + 3
  return offset
end

-- main dissector
function packet_ppi_proto.dissector(buffer, pinfo, tree)
  pinfo.cols.protocol = "packet_ppi"
  local main = tree:add(packet_ppi_proto, buffer(), "packet_ppi")
  local offset = 0

  offset = parse_packet_ppi_header(buffer, main, offset)
  offset = parse_packet_ppi_fields(buffer, main, offset)
  -- body: manual implementation needed (complex size/type)
end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(0, packet_ppi_proto)
