protocol_body_proto = Proto("protocol_body","protocol_body file")

local f = protocol_body_proto.fields

-- field declarations
f.body = ProtoField.bytes("protocol_body.body", "body")
f.next_header_type = ProtoField.bytes("protocol_body.option_hop_by_hop.next_header_type", "next_header_type")
f.hdr_ext_len = ProtoField.bytes("protocol_body.option_hop_by_hop.hdr_ext_len", "hdr_ext_len")
f.body = ProtoField.bytes("protocol_body.option_hop_by_hop.body", "body")
f.next_header = ProtoField.bytes("protocol_body.option_hop_by_hop.next_header", "next_header")

-- sub-type parsers
local function parse_no_next_header(buffer, tree, offset)
  local sub = tree:add("no_next_header")
  return offset
end

local function parse_option_hop_by_hop(buffer, tree, offset)
  local sub = tree:add("option_hop_by_hop")
  local next_header_type_val = buffer(offset, 1):uint()
  sub:add(f.next_header_type, buffer(offset, 1)); offset = offset + 1
  local hdr_ext_len_val = buffer(offset, 1):uint()
  sub:add(f.hdr_ext_len, buffer(offset, 1)); offset = offset + 1
  local body_size = hdr_ext_len > 0 ? hdr_ext_len - 1 : 1_val
  sub:add(f.body, buffer(offset, body_size)); offset = offset + body_size
  -- next_header: manual implementation needed
  return offset
end

-- main dissector
function protocol_body_proto.dissector(buffer, pinfo, tree)
  pinfo.cols.protocol = "protocol_body"
  local main = tree:add(protocol_body_proto, buffer(), "protocol_body")
  local offset = 0

  -- body: manual implementation needed
end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(0, protocol_body_proto)
