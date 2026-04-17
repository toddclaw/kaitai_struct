dns_packet_proto = Proto("kaitai_dns_packet","dns_packet file")

local f = dns_packet_proto.fields

-- field declarations
f.transaction_id = ProtoField.bytes("kaitai_dns_packet.transaction_id", "transaction_id")
f.flags = ProtoField.bytes("kaitai_dns_packet.flags", "flags")
f.qdcount = ProtoField.bytes("kaitai_dns_packet.qdcount", "qdcount")
f.ancount = ProtoField.bytes("kaitai_dns_packet.ancount", "ancount")
f.nscount = ProtoField.bytes("kaitai_dns_packet.nscount", "nscount")
f.arcount = ProtoField.bytes("kaitai_dns_packet.arcount", "arcount")
f.queries = ProtoField.bytes("kaitai_dns_packet.queries", "queries")
f.answers = ProtoField.bytes("kaitai_dns_packet.answers", "answers")
f.authorities = ProtoField.bytes("kaitai_dns_packet.authorities", "authorities")
f.additionals = ProtoField.bytes("kaitai_dns_packet.additionals", "additionals")
f.name = ProtoField.bytes("kaitai_dns_packet.query.name", "name")
f.type = ProtoField.bytes("kaitai_dns_packet.query.type", "type")
f.query_class = ProtoField.bytes("kaitai_dns_packet.query.query_class", "query_class")
f.name = ProtoField.bytes("kaitai_dns_packet.answer.name", "name")
f.type = ProtoField.bytes("kaitai_dns_packet.answer.type", "type")
f.answer_class = ProtoField.bytes("kaitai_dns_packet.answer.answer_class", "answer_class")
f.ttl = ProtoField.bytes("kaitai_dns_packet.answer.ttl", "ttl")
f.rdlength = ProtoField.bytes("kaitai_dns_packet.answer.rdlength", "rdlength")
f.payload = ProtoField.bytes("kaitai_dns_packet.answer.payload", "payload")
f.name = ProtoField.bytes("kaitai_dns_packet.domain_name.name", "name")
f.length = ProtoField.bytes("kaitai_dns_packet.label.length", "length")
f.pointer = ProtoField.bytes("kaitai_dns_packet.label.pointer", "pointer")
f.name = ProtoField.bytes("kaitai_dns_packet.label.name", "name")
f.value = ProtoField.bytes("kaitai_dns_packet.pointer_struct.value", "value")
f.ip = ProtoField.bytes("kaitai_dns_packet.address.ip", "ip")
f.ip_v6 = ProtoField.bytes("kaitai_dns_packet.address_v6.ip_v6", "ip_v6")
f.flag = ProtoField.bytes("kaitai_dns_packet.packet_flags.flag", "flag")
f.priority = ProtoField.bytes("kaitai_dns_packet.service.priority", "priority")
f.weight = ProtoField.bytes("kaitai_dns_packet.service.weight", "weight")
f.port = ProtoField.bytes("kaitai_dns_packet.service.port", "port")
f.target = ProtoField.bytes("kaitai_dns_packet.service.target", "target")
f.length = ProtoField.bytes("kaitai_dns_packet.txt.length", "length")
f.text = ProtoField.bytes("kaitai_dns_packet.txt.text", "text")
f.data = ProtoField.bytes("kaitai_dns_packet.txt_body.data", "data")
f.primary_ns = ProtoField.bytes("kaitai_dns_packet.authority_info.primary_ns", "primary_ns")
f.resoponsible_mailbox = ProtoField.bytes("kaitai_dns_packet.authority_info.resoponsible_mailbox", "resoponsible_mailbox")
f.serial = ProtoField.bytes("kaitai_dns_packet.authority_info.serial", "serial")
f.refresh_interval = ProtoField.bytes("kaitai_dns_packet.authority_info.refresh_interval", "refresh_interval")
f.retry_interval = ProtoField.bytes("kaitai_dns_packet.authority_info.retry_interval", "retry_interval")
f.expire_limit = ProtoField.bytes("kaitai_dns_packet.authority_info.expire_limit", "expire_limit")
f.min_ttl = ProtoField.bytes("kaitai_dns_packet.authority_info.min_ttl", "min_ttl")
f.preference = ProtoField.bytes("kaitai_dns_packet.mx_info.preference", "preference")
f.mx = ProtoField.bytes("kaitai_dns_packet.mx_info.mx", "mx")

-- sub-type parsers
local function parse_query(buffer, tree, offset)
  local subtree = tree:add("query")
  -- name: manual implementation needed (complex size/type)
  local type_val = buffer(offset, 2):uint()
  subtree:add(f.type, buffer(offset, 2)); offset = offset + 2
  local query_class_val = buffer(offset, 2):uint()
  subtree:add(f.query_class, buffer(offset, 2)); offset = offset + 2
  return offset
end

local function parse_answer(buffer, tree, offset)
  local subtree = tree:add("answer")
  -- name: manual implementation needed (complex size/type)
  local type_val = buffer(offset, 2):uint()
  subtree:add(f.type, buffer(offset, 2)); offset = offset + 2
  local answer_class_val = buffer(offset, 2):uint()
  subtree:add(f.answer_class, buffer(offset, 2)); offset = offset + 2
  -- ttl: manual implementation needed (complex size/type)
  local rdlength_val = buffer(offset, 2):uint()
  subtree:add(f.rdlength, buffer(offset, 2)); offset = offset + 2
  local payload_size = rdlength_val
  subtree:add(f.payload, buffer(offset, payload_size)); offset = offset + payload_size
  return offset
end

local function parse_domain_name(buffer, tree, offset)
  local subtree = tree:add("domain_name")
  -- name: manual implementation needed (complex size/type)
  return offset
end

local function parse_label(buffer, tree, offset)
  local subtree = tree:add("label")
  local length_val = buffer(offset, 1):uint()
  subtree:add(f.length, buffer(offset, 1)); offset = offset + 1
  -- pointer: manual implementation needed (complex size/type)
  local name_size = length_val
  subtree:add(f.name, buffer(offset, name_size)); offset = offset + name_size
  return offset
end

local function parse_pointer_struct(buffer, tree, offset)
  local subtree = tree:add("pointer_struct")
  local value_val = buffer(offset, 1):uint()
  subtree:add(f.value, buffer(offset, 1)); offset = offset + 1
  return offset
end

local function parse_address(buffer, tree, offset)
  local subtree = tree:add("address")
  subtree:add(f.ip, buffer(offset, 4)); offset = offset + 4
  return offset
end

local function parse_address_v6(buffer, tree, offset)
  local subtree = tree:add("address_v6")
  subtree:add(f.ip_v6, buffer(offset, 16)); offset = offset + 16
  return offset
end

local function parse_packet_flags(buffer, tree, offset)
  local subtree = tree:add("packet_flags")
  local flag_val = buffer(offset, 2):uint()
  subtree:add(f.flag, buffer(offset, 2)); offset = offset + 2
  return offset
end

local function parse_service(buffer, tree, offset)
  local subtree = tree:add("service")
  local priority_val = buffer(offset, 2):uint()
  subtree:add(f.priority, buffer(offset, 2)); offset = offset + 2
  local weight_val = buffer(offset, 2):uint()
  subtree:add(f.weight, buffer(offset, 2)); offset = offset + 2
  local port_val = buffer(offset, 2):uint()
  subtree:add(f.port, buffer(offset, 2)); offset = offset + 2
  -- target: manual implementation needed (complex size/type)
  return offset
end

local function parse_txt(buffer, tree, offset)
  local subtree = tree:add("txt")
  local length_val = buffer(offset, 1):uint()
  subtree:add(f.length, buffer(offset, 1)); offset = offset + 1
  local text_size = length_val
  subtree:add(f.text, buffer(offset, text_size)); offset = offset + text_size
  return offset
end

local function parse_txt_body(buffer, tree, offset)
  local subtree = tree:add("txt_body")
  -- data: manual implementation needed (complex size/type)
  return offset
end

local function parse_authority_info(buffer, tree, offset)
  local subtree = tree:add("authority_info")
  -- primary_ns: manual implementation needed (complex size/type)
  -- resoponsible_mailbox: manual implementation needed (complex size/type)
  local serial_val = buffer(offset, 4):uint()
  subtree:add(f.serial, buffer(offset, 4)); offset = offset + 4
  local refresh_interval_val = buffer(offset, 4):uint()
  subtree:add(f.refresh_interval, buffer(offset, 4)); offset = offset + 4
  local retry_interval_val = buffer(offset, 4):uint()
  subtree:add(f.retry_interval, buffer(offset, 4)); offset = offset + 4
  local expire_limit_val = buffer(offset, 4):uint()
  subtree:add(f.expire_limit, buffer(offset, 4)); offset = offset + 4
  local min_ttl_val = buffer(offset, 4):uint()
  subtree:add(f.min_ttl, buffer(offset, 4)); offset = offset + 4
  return offset
end

local function parse_mx_info(buffer, tree, offset)
  local subtree = tree:add("mx_info")
  local preference_val = buffer(offset, 2):uint()
  subtree:add(f.preference, buffer(offset, 2)); offset = offset + 2
  -- mx: manual implementation needed (complex size/type)
  return offset
end

-- main dissector
function dns_packet_proto.dissector(buffer, pinfo, tree)
  pinfo.cols.protocol = "dns_packet"
  local main = tree:add(dns_packet_proto, buffer(), "dns_packet")
  local offset = 0

  local transaction_id_val = buffer(offset, 2):uint()
  main:add(f.transaction_id, buffer(offset, 2)); offset = offset + 2
  offset = parse_packet_flags(buffer, main, offset)
  local qdcount_val = buffer(offset, 2):uint()
  main:add(f.qdcount, buffer(offset, 2)); offset = offset + 2
  local ancount_val = buffer(offset, 2):uint()
  main:add(f.ancount, buffer(offset, 2)); offset = offset + 2
  local nscount_val = buffer(offset, 2):uint()
  main:add(f.nscount, buffer(offset, 2)); offset = offset + 2
  local arcount_val = buffer(offset, 2):uint()
  main:add(f.arcount, buffer(offset, 2)); offset = offset + 2
  for _i = 1, qdcount_val do
    offset = parse_query(buffer, main, offset)
  end
  for _i = 1, ancount_val do
    offset = parse_answer(buffer, main, offset)
  end
  for _i = 1, nscount_val do
    offset = parse_answer(buffer, main, offset)
  end
  for _i = 1, arcount_val do
    offset = parse_answer(buffer, main, offset)
  end
end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(0, dns_packet_proto)
