dime_message_proto = Proto("kaitai_dime_message","dime_message file")

local f = dime_message_proto.fields

-- field declarations
f.records = ProtoField.bytes("dime_message.records", "records")
f.boundary_padding = ProtoField.bytes("dime_message.padding.boundary_padding", "boundary_padding")
f.option_elements = ProtoField.bytes("dime_message.option_field.option_elements", "option_elements")
f.element_format = ProtoField.bytes("dime_message.option_element.element_format", "element_format")
f.len_element = ProtoField.bytes("dime_message.option_element.len_element", "len_element")
f.element_data = ProtoField.bytes("dime_message.option_element.element_data", "element_data")
f.version = ProtoField.bytes("dime_message.record.version", "version")
f.is_first_record = ProtoField.bytes("dime_message.record.is_first_record", "is_first_record")
f.is_last_record = ProtoField.bytes("dime_message.record.is_last_record", "is_last_record")
f.is_chunk_record = ProtoField.bytes("dime_message.record.is_chunk_record", "is_chunk_record")
f.type_format = ProtoField.bytes("dime_message.record.type_format", "type_format")
f.reserved = ProtoField.bytes("dime_message.record.reserved", "reserved")
f.len_options = ProtoField.bytes("dime_message.record.len_options", "len_options")
f.len_id = ProtoField.bytes("dime_message.record.len_id", "len_id")
f.len_type = ProtoField.bytes("dime_message.record.len_type", "len_type")
f.len_data = ProtoField.bytes("dime_message.record.len_data", "len_data")
f.options = ProtoField.bytes("dime_message.record.options", "options")
f.options_padding = ProtoField.bytes("dime_message.record.options_padding", "options_padding")
f.id = ProtoField.bytes("dime_message.record.id", "id")
f.id_padding = ProtoField.bytes("dime_message.record.id_padding", "id_padding")
f.type = ProtoField.bytes("dime_message.record.type", "type")
f.type_padding = ProtoField.bytes("dime_message.record.type_padding", "type_padding")
f.data = ProtoField.bytes("dime_message.record.data", "data")
f.data_padding = ProtoField.bytes("dime_message.record.data_padding", "data_padding")

-- sub-type parsers
local function parse_padding(buffer, tree, offset)
  local subtree = tree:add("padding")
  -- boundary_padding: manual implementation needed (complex size/type)
  return offset
end

local function parse_option_field(buffer, tree, offset)
  local subtree = tree:add("option_field")
  -- option_elements: manual implementation needed (complex size/type)
  return offset
end

local function parse_option_element(buffer, tree, offset)
  local subtree = tree:add("option_element")
  local element_format_val = buffer(offset, 2):uint()
  subtree:add(f.element_format, buffer(offset, 2)); offset = offset + 2
  local len_element_val = buffer(offset, 2):uint()
  subtree:add(f.len_element, buffer(offset, 2)); offset = offset + 2
  local element_data_size = len_element_val
  subtree:add(f.element_data, buffer(offset, element_data_size)); offset = offset + element_data_size
  return offset
end

local function parse_record(buffer, tree, offset)
  local subtree = tree:add("record")
  -- version: manual implementation needed (complex size/type)
  -- is_first_record: manual implementation needed (complex size/type)
  -- is_last_record: manual implementation needed (complex size/type)
  -- is_chunk_record: manual implementation needed (complex size/type)
  -- type_format: manual implementation needed (complex size/type)
  -- reserved: manual implementation needed (complex size/type)
  local len_options_val = buffer(offset, 2):uint()
  subtree:add(f.len_options, buffer(offset, 2)); offset = offset + 2
  local len_id_val = buffer(offset, 2):uint()
  subtree:add(f.len_id, buffer(offset, 2)); offset = offset + 2
  local len_type_val = buffer(offset, 2):uint()
  subtree:add(f.len_type, buffer(offset, 2)); offset = offset + 2
  local len_data_val = buffer(offset, 4):uint()
  subtree:add(f.len_data, buffer(offset, 4)); offset = offset + 4
  local options_size = len_options_val
  subtree:add(f.options, buffer(offset, options_size)); offset = offset + options_size
  -- options_padding: manual implementation needed (complex size/type)
  local id_size = len_id_val
  subtree:add(f.id, buffer(offset, id_size)); offset = offset + id_size
  -- id_padding: manual implementation needed (complex size/type)
  local type_size = len_type_val
  subtree:add(f.type, buffer(offset, type_size)); offset = offset + type_size
  -- type_padding: manual implementation needed (complex size/type)
  local data_size = len_data_val
  subtree:add(f.data, buffer(offset, data_size)); offset = offset + data_size
  -- data_padding: manual implementation needed (complex size/type)
  return offset
end

-- main dissector
function dime_message_proto.dissector(buffer, pinfo, tree)
  pinfo.cols.protocol = "dime_message"
  local main = tree:add(dime_message_proto, buffer(), "dime_message")
  local offset = 0

  offset = parse_record(buffer, main, offset)
end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(0, dime_message_proto)
