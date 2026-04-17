test_sample_proto = Proto("test_sample","test_sample file")

local f = test_sample_proto.fields

-- field declaration
f.magic = ProtoField.bytes("test_sample.magic", "magic")
f.version = ProtoField.bytes("test_sample.version", "version")
f.length = ProtoField.bytes("test_sample.length", "length")
f.payload = ProtoField.bytes("test_sample.payload", "payload")

-- main function
function test_sample_proto.dissector(buffer,pinfo,tree)
  pinfo.cols.protocol = "test_sample"

  main = tree:add(test_sample_proto, "test_sample file")

end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(8001, test_sample_proto)
