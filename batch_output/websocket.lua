websocket_proto = Proto("websocket","websocket file")

local f = websocket_proto.fields

-- field declarations
f.initial_frame = ProtoField.bytes("websocket.initial_frame", "initial_frame")
f.trailing_frames = ProtoField.bytes("websocket.trailing_frames", "trailing_frames")
f.finished = ProtoField.bytes("websocket.frame_header.finished", "finished")
f.reserved = ProtoField.bytes("websocket.frame_header.reserved", "reserved")
f.opcode = ProtoField.bytes("websocket.frame_header.opcode", "opcode")
f.is_masked = ProtoField.bytes("websocket.frame_header.is_masked", "is_masked")
f.len_payload_primary = ProtoField.bytes("websocket.frame_header.len_payload_primary", "len_payload_primary")
f.len_payload_extended_1 = ProtoField.bytes("websocket.frame_header.len_payload_extended_1", "len_payload_extended_1")
f.len_payload_extended_2 = ProtoField.bytes("websocket.frame_header.len_payload_extended_2", "len_payload_extended_2")
f.mask_key = ProtoField.bytes("websocket.frame_header.mask_key", "mask_key")
f.header = ProtoField.bytes("websocket.initial_frame.header", "header")
f.payload_bytes = ProtoField.bytes("websocket.initial_frame.payload_bytes", "payload_bytes")
f.payload_text = ProtoField.bytes("websocket.initial_frame.payload_text", "payload_text")
f.header = ProtoField.bytes("websocket.dataframe.header", "header")
f.payload_bytes = ProtoField.bytes("websocket.dataframe.payload_bytes", "payload_bytes")
f.payload_text = ProtoField.bytes("websocket.dataframe.payload_text", "payload_text")

-- sub-type parsers
local function parse_frame_header(buffer, tree, offset)
  local sub = tree:add("frame_header")
  -- finished: manual implementation needed
  -- reserved: manual implementation needed
  -- opcode: manual implementation needed
  -- is_masked: manual implementation needed
  -- len_payload_primary: manual implementation needed
  local len_payload_extended_1_val = buffer(offset, 2):uint()
  sub:add(f.len_payload_extended_1, buffer(offset, 2)); offset = offset + 2
  local len_payload_extended_2_val = buffer(offset, 4):uint()
  sub:add(f.len_payload_extended_2, buffer(offset, 4)); offset = offset + 4
  local mask_key_val = buffer(offset, 4):uint()
  sub:add(f.mask_key, buffer(offset, 4)); offset = offset + 4
  return offset
end

local function parse_initial_frame(buffer, tree, offset)
  local sub = tree:add("initial_frame")
  -- header: manual implementation needed
  local payload_bytes_size = header.len_payload_val
  sub:add(f.payload_bytes, buffer(offset, payload_bytes_size)); offset = offset + payload_bytes_size
  local payload_text_size = header.len_payload_val
  sub:add(f.payload_text, buffer(offset, payload_text_size)); offset = offset + payload_text_size
  return offset
end

local function parse_dataframe(buffer, tree, offset)
  local sub = tree:add("dataframe")
  -- header: manual implementation needed
  local payload_bytes_size = header.len_payload_val
  sub:add(f.payload_bytes, buffer(offset, payload_bytes_size)); offset = offset + payload_bytes_size
  local payload_text_size = header.len_payload_val
  sub:add(f.payload_text, buffer(offset, payload_text_size)); offset = offset + payload_text_size
  return offset
end

-- main dissector
function websocket_proto.dissector(buffer, pinfo, tree)
  pinfo.cols.protocol = "websocket"
  local main = tree:add(websocket_proto, buffer(), "websocket")
  local offset = 0

  offset = parse_initial_frame(buffer, main, offset)
  offset = parse_dataframe(buffer, main, offset)
end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(0, websocket_proto)
