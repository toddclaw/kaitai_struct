tls_client_hello_proto = Proto("tls_client_hello","tls_client_hello file")

local f = tls_client_hello_proto.fields

-- field declarations
f.version = ProtoField.bytes("tls_client_hello.version", "version")
f.random = ProtoField.bytes("tls_client_hello.random", "random")
f.session_id = ProtoField.bytes("tls_client_hello.session_id", "session_id")
f.cipher_suites = ProtoField.bytes("tls_client_hello.cipher_suites", "cipher_suites")
f.compression_methods = ProtoField.bytes("tls_client_hello.compression_methods", "compression_methods")
f.extensions = ProtoField.bytes("tls_client_hello.extensions", "extensions")
f.major = ProtoField.bytes("tls_client_hello.version.major", "major")
f.minor = ProtoField.bytes("tls_client_hello.version.minor", "minor")
f.gmt_unix_time = ProtoField.bytes("tls_client_hello.random.gmt_unix_time", "gmt_unix_time")
f.random = ProtoField.bytes("tls_client_hello.random.random", "random")
f.len = ProtoField.bytes("tls_client_hello.session_id.len", "len")
f.sid = ProtoField.bytes("tls_client_hello.session_id.sid", "sid")
f.len = ProtoField.bytes("tls_client_hello.cipher_suites.len", "len")
f.cipher_suites = ProtoField.bytes("tls_client_hello.cipher_suites.cipher_suites", "cipher_suites")
f.len = ProtoField.bytes("tls_client_hello.compression_methods.len", "len")
f.compression_methods = ProtoField.bytes("tls_client_hello.compression_methods.compression_methods", "compression_methods")
f.len = ProtoField.bytes("tls_client_hello.extensions.len", "len")
f.extensions = ProtoField.bytes("tls_client_hello.extensions.extensions", "extensions")
f.type = ProtoField.bytes("tls_client_hello.extension.type", "type")
f.len = ProtoField.bytes("tls_client_hello.extension.len", "len")
f.body = ProtoField.bytes("tls_client_hello.extension.body", "body")
f.list_length = ProtoField.bytes("tls_client_hello.sni.list_length", "list_length")
f.server_names = ProtoField.bytes("tls_client_hello.sni.server_names", "server_names")
f.name_type = ProtoField.bytes("tls_client_hello.server_name.name_type", "name_type")
f.length = ProtoField.bytes("tls_client_hello.server_name.length", "length")
f.host_name = ProtoField.bytes("tls_client_hello.server_name.host_name", "host_name")
f.ext_len = ProtoField.bytes("tls_client_hello.alpn.ext_len", "ext_len")
f.alpn_protocols = ProtoField.bytes("tls_client_hello.alpn.alpn_protocols", "alpn_protocols")
f.strlen = ProtoField.bytes("tls_client_hello.protocol.strlen", "strlen")
f.name = ProtoField.bytes("tls_client_hello.protocol.name", "name")

-- sub-type parsers
local function parse_version(buffer, tree, offset)
  local sub = tree:add("version")
  local major_val = buffer(offset, 1):uint()
  sub:add(f.major, buffer(offset, 1)); offset = offset + 1
  local minor_val = buffer(offset, 1):uint()
  sub:add(f.minor, buffer(offset, 1)); offset = offset + 1
  return offset
end

local function parse_random(buffer, tree, offset)
  local sub = tree:add("random")
  local gmt_unix_time_val = buffer(offset, 4):uint()
  sub:add(f.gmt_unix_time, buffer(offset, 4)); offset = offset + 4
  sub:add(f.random, buffer(offset, 28)); offset = offset + 28
  return offset
end

local function parse_session_id(buffer, tree, offset)
  local sub = tree:add("session_id")
  local len_val = buffer(offset, 1):uint()
  sub:add(f.len, buffer(offset, 1)); offset = offset + 1
  local sid_size = len_val
  sub:add(f.sid, buffer(offset, sid_size)); offset = offset + sid_size
  return offset
end

local function parse_cipher_suites(buffer, tree, offset)
  local sub = tree:add("cipher_suites")
  local len_val = buffer(offset, 2):uint()
  sub:add(f.len, buffer(offset, 2)); offset = offset + 2
  local cipher_suites_val = buffer(offset, 2):uint()
  sub:add(f.cipher_suites, buffer(offset, 2)); offset = offset + 2
  return offset
end

local function parse_compression_methods(buffer, tree, offset)
  local sub = tree:add("compression_methods")
  local len_val = buffer(offset, 1):uint()
  sub:add(f.len, buffer(offset, 1)); offset = offset + 1
  local compression_methods_size = len_val
  sub:add(f.compression_methods, buffer(offset, compression_methods_size)); offset = offset + compression_methods_size
  return offset
end

local function parse_extensions(buffer, tree, offset)
  local sub = tree:add("extensions")
  local len_val = buffer(offset, 2):uint()
  sub:add(f.len, buffer(offset, 2)); offset = offset + 2
  -- extensions: manual implementation needed
  return offset
end

local function parse_extension(buffer, tree, offset)
  local sub = tree:add("extension")
  local type_val = buffer(offset, 2):uint()
  sub:add(f.type, buffer(offset, 2)); offset = offset + 2
  local len_val = buffer(offset, 2):uint()
  sub:add(f.len, buffer(offset, 2)); offset = offset + 2
  local body_size = len_val
  sub:add(f.body, buffer(offset, body_size)); offset = offset + body_size
  return offset
end

local function parse_sni(buffer, tree, offset)
  local sub = tree:add("sni")
  local list_length_val = buffer(offset, 2):uint()
  sub:add(f.list_length, buffer(offset, 2)); offset = offset + 2
  -- server_names: manual implementation needed
  return offset
end

local function parse_server_name(buffer, tree, offset)
  local sub = tree:add("server_name")
  local name_type_val = buffer(offset, 1):uint()
  sub:add(f.name_type, buffer(offset, 1)); offset = offset + 1
  local length_val = buffer(offset, 2):uint()
  sub:add(f.length, buffer(offset, 2)); offset = offset + 2
  local host_name_size = length_val
  sub:add(f.host_name, buffer(offset, host_name_size)); offset = offset + host_name_size
  return offset
end

local function parse_alpn(buffer, tree, offset)
  local sub = tree:add("alpn")
  local ext_len_val = buffer(offset, 2):uint()
  sub:add(f.ext_len, buffer(offset, 2)); offset = offset + 2
  -- alpn_protocols: manual implementation needed
  return offset
end

local function parse_protocol(buffer, tree, offset)
  local sub = tree:add("protocol")
  local strlen_val = buffer(offset, 1):uint()
  sub:add(f.strlen, buffer(offset, 1)); offset = offset + 1
  local name_size = strlen_val
  sub:add(f.name, buffer(offset, name_size)); offset = offset + name_size
  return offset
end

-- main dissector
function tls_client_hello_proto.dissector(buffer, pinfo, tree)
  pinfo.cols.protocol = "tls_client_hello"
  local main = tree:add(tls_client_hello_proto, buffer(), "tls_client_hello")
  local offset = 0

  offset = parse_version(buffer, main, offset)
  offset = parse_random(buffer, main, offset)
  offset = parse_session_id(buffer, main, offset)
  offset = parse_cipher_suites(buffer, main, offset)
  offset = parse_compression_methods(buffer, main, offset)
  offset = parse_extensions(buffer, main, offset)
end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(0, tls_client_hello_proto)
