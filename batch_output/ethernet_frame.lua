ethernet_frame_proto = Proto("kaitai_ethernet_frame","ethernet_frame file")

local f = ethernet_frame_proto.fields

-- field declarations
f.dst_mac = ProtoField.bytes("kaitai_ethernet_frame.dst_mac", "dst_mac")
f.src_mac = ProtoField.bytes("kaitai_ethernet_frame.src_mac", "src_mac")
f.ether_type_1 = ProtoField.bytes("kaitai_ethernet_frame.ether_type_1", "ether_type_1")
f.tci = ProtoField.bytes("kaitai_ethernet_frame.tci", "tci")
f.ether_type_2 = ProtoField.bytes("kaitai_ethernet_frame.ether_type_2", "ether_type_2")
f.body = ProtoField.bytes("kaitai_ethernet_frame.body", "body")
f.priority = ProtoField.bytes("kaitai_ethernet_frame.tag_control_info.priority", "priority")
f.drop_eligible = ProtoField.bytes("kaitai_ethernet_frame.tag_control_info.drop_eligible", "drop_eligible")
f.vlan_id = ProtoField.bytes("kaitai_ethernet_frame.tag_control_info.vlan_id", "vlan_id")

-- sub-type parsers
local function parse_tag_control_info(buffer, tree, offset)
  local subtree = tree:add("tag_control_info")
  -- priority: manual implementation needed (complex size/type)
  -- drop_eligible: manual implementation needed (complex size/type)
  -- vlan_id: manual implementation needed (complex size/type)
  return offset
end

-- main dissector
function ethernet_frame_proto.dissector(buffer, pinfo, tree)
  pinfo.cols.protocol = "ethernet_frame"
  local main = tree:add(ethernet_frame_proto, buffer(), "ethernet_frame")
  local offset = 0

  main:add(f.dst_mac, buffer(offset, 6)); offset = offset + 6
  main:add(f.src_mac, buffer(offset, 6)); offset = offset + 6
  local ether_type_1_val = buffer(offset, 2):uint()
  main:add(f.ether_type_1, buffer(offset, 2)); offset = offset + 2
  offset = parse_tag_control_info(buffer, main, offset)
  local ether_type_2_val = buffer(offset, 2):uint()
  main:add(f.ether_type_2, buffer(offset, 2)); offset = offset + 2
  -- body: manual implementation needed (complex size/type)
end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(0, ethernet_frame_proto)
