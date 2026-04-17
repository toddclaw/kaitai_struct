test_sample_proto = Proto("kaitai_test_sample","test_sample file")

local f = test_sample_proto.fields

-- field declarations
f.magic = ProtoField.bytes("test_sample.magic", "magic")
f.version = ProtoField.bytes("test_sample.version", "version")
f.length = ProtoField.bytes("test_sample.length", "length")
f.payload = ProtoField.bytes("test_sample.payload", "payload")

-- sub-type parsers
-- main dissector
function test_sample_proto.dissector(buffer, pinfo, tree)
  pinfo.cols.protocol = "test_sample"
  local main = tree:add(test_sample_proto, buffer(), "test_sample")
  local offset = 0

  main:add(f.magic, buffer(offset, 2)); offset = offset + 2
  local version_val = buffer(offset, 1):uint()
  main:add(f.version, buffer(offset, 1)); offset = offset + 1
  local length_val = buffer(offset, 2):uint()
  main:add(f.length, buffer(offset, 2)); offset = offset + 2
  -- payload: manual implementation needed (complex size/type)
end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(8001, test_sample_proto)
