bitcoin_transaction_proto = Proto("kaitai_bitcoin_transaction","bitcoin_transaction file")

local f = bitcoin_transaction_proto.fields

-- field declarations
f.version = ProtoField.bytes("kaitai_bitcoin_transaction.version", "version")
f.num_vins = ProtoField.bytes("kaitai_bitcoin_transaction.num_vins", "num_vins")
f.vins = ProtoField.bytes("kaitai_bitcoin_transaction.vins", "vins")
f.num_vouts = ProtoField.bytes("kaitai_bitcoin_transaction.num_vouts", "num_vouts")
f.vouts = ProtoField.bytes("kaitai_bitcoin_transaction.vouts", "vouts")
f.locktime = ProtoField.bytes("kaitai_bitcoin_transaction.locktime", "locktime")
f.txid = ProtoField.bytes("kaitai_bitcoin_transaction.vin.txid", "txid")
f.output_id = ProtoField.bytes("kaitai_bitcoin_transaction.vin.output_id", "output_id")
f.len_script = ProtoField.bytes("kaitai_bitcoin_transaction.vin.len_script", "len_script")
f.script_sig = ProtoField.bytes("kaitai_bitcoin_transaction.vin.script_sig", "script_sig")
f.end_of_vin = ProtoField.bytes("kaitai_bitcoin_transaction.vin.end_of_vin", "end_of_vin")
f.amount = ProtoField.bytes("kaitai_bitcoin_transaction.vout.amount", "amount")
f.len_script = ProtoField.bytes("kaitai_bitcoin_transaction.vout.len_script", "len_script")
f.script_pub_key = ProtoField.bytes("kaitai_bitcoin_transaction.vout.script_pub_key", "script_pub_key")

-- sub-type parsers
local function parse_vin(buffer, tree, offset)
  local subtree = tree:add("vin")
  subtree:add(f.txid, buffer(offset, 32)); offset = offset + 32
  local output_id_val = buffer(offset, 4):uint()
  subtree:add(f.output_id, buffer(offset, 4)); offset = offset + 4
  local len_script_val = buffer(offset, 1):uint()
  subtree:add(f.len_script, buffer(offset, 1)); offset = offset + 1
  local script_sig_size = len_script_val
  subtree:add(f.script_sig, buffer(offset, script_sig_size)); offset = offset + script_sig_size
  subtree:add(f.end_of_vin, buffer(offset, 4)); offset = offset + 4
  return offset
end

local function parse_vout(buffer, tree, offset)
  local subtree = tree:add("vout")
  -- amount: manual implementation needed (complex size/type)
  local len_script_val = buffer(offset, 1):uint()
  subtree:add(f.len_script, buffer(offset, 1)); offset = offset + 1
  local script_pub_key_size = len_script_val
  subtree:add(f.script_pub_key, buffer(offset, script_pub_key_size)); offset = offset + script_pub_key_size
  return offset
end

-- main dissector
function bitcoin_transaction_proto.dissector(buffer, pinfo, tree)
  pinfo.cols.protocol = "bitcoin_transaction"
  local main = tree:add(bitcoin_transaction_proto, buffer(), "bitcoin_transaction")
  local offset = 0

  local version_val = buffer(offset, 4):uint()
  main:add(f.version, buffer(offset, 4)); offset = offset + 4
  local num_vins_val = buffer(offset, 1):uint()
  main:add(f.num_vins, buffer(offset, 1)); offset = offset + 1
  for _i = 1, num_vins_val do
    offset = parse_vin(buffer, main, offset)
  end
  local num_vouts_val = buffer(offset, 1):uint()
  main:add(f.num_vouts, buffer(offset, 1)); offset = offset + 1
  for _i = 1, num_vouts_val do
    offset = parse_vout(buffer, main, offset)
  end
  local locktime_val = buffer(offset, 4):uint()
  main:add(f.locktime, buffer(offset, 4)); offset = offset + 4
end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(0, bitcoin_transaction_proto)
