{{data.meta.id}}_proto = Proto("{{data.meta.id}}","{{data.meta.id}} file")

local f = {{data.meta.id}}_proto.fields

-- field declarations
{% for item in data.seq %}
f.{{item.id}} = ProtoField.bytes("{{data.meta.id}}.{{item.id}}", "{{item.id}}")
{% endfor %}
{% for typename, typedata in (data["types"] | default({})).items() %}
{% for seqitem in typedata.seq %}
f.{{seqitem.id}} = ProtoField.bytes("{{data.meta.id}}.{{typename}}.{{seqitem.id}}", "{{seqitem.id}}")
{% endfor %}
{% endfor %}

-- sub-type parsers
{% for typename, typedata in (data["types"] | default({})).items() %}
local function parse_{{typename}}(buffer, tree, offset)
  local sub = tree:add("{{typename}}")
{% for seqitem in typedata.seq %}
{% if seqitem.type is defined and seqitem.type == "u1" %}
  local {{seqitem.id}}_val = buffer(offset, 1):uint()
  sub:add(f.{{seqitem.id}}, buffer(offset, 1)); offset = offset + 1
{% elif seqitem.type is defined and seqitem.type in ["u2", "u2be", "u2le"] %}
  local {{seqitem.id}}_val = buffer(offset, 2):uint()
  sub:add(f.{{seqitem.id}}, buffer(offset, 2)); offset = offset + 2
{% elif seqitem.type is defined and seqitem.type in ["u4", "u4be", "u4le"] %}
  local {{seqitem.id}}_val = buffer(offset, 4):uint()
  sub:add(f.{{seqitem.id}}, buffer(offset, 4)); offset = offset + 4
{% elif seqitem.contents is defined %}
  sub:add(f.{{seqitem.id}}, buffer(offset, {{seqitem.contents|length}})); offset = offset + {{seqitem.contents|length}}
{% elif seqitem.size is defined and seqitem.size is integer %}
  sub:add(f.{{seqitem.id}}, buffer(offset, {{seqitem.size}})); offset = offset + {{seqitem.size}}
{% elif seqitem.size is defined %}
  local {{seqitem.id}}_size = {{seqitem.size}}_val
  sub:add(f.{{seqitem.id}}, buffer(offset, {{seqitem.id}}_size)); offset = offset + {{seqitem.id}}_size
{% else %}
  -- {{seqitem.id}}: manual implementation needed
{% endif %}
{% endfor %}
  return offset
end

{% endfor %}
-- main dissector
function {{data.meta.id}}_proto.dissector(buffer, pinfo, tree)
  pinfo.cols.protocol = "{{data.meta.id}}"
  local main = tree:add({{data.meta.id}}_proto, buffer(), "{{data.meta.id}}")
  local offset = 0

{% for item in data.seq %}
{% if item.type is defined and item.type == "u1" %}
  local {{item.id}}_val = buffer(offset, 1):uint()
  main:add(f.{{item.id}}, buffer(offset, 1)); offset = offset + 1
{% elif item.type is defined and item.type in ["u2", "u2be", "u2le"] %}
  local {{item.id}}_val = buffer(offset, 2):uint()
  main:add(f.{{item.id}}, buffer(offset, 2)); offset = offset + 2
{% elif item.type is defined and item.type in ["u4", "u4be", "u4le"] %}
  local {{item.id}}_val = buffer(offset, 4):uint()
  main:add(f.{{item.id}}, buffer(offset, 4)); offset = offset + 4
{% elif item.contents is defined %}
  main:add(f.{{item.id}}, buffer(offset, {{item.contents|length}})); offset = offset + {{item.contents|length}}
{% elif item.size is defined and item.size is integer %}
  main:add(f.{{item.id}}, buffer(offset, {{item.size}})); offset = offset + {{item.size}}
{% elif item.type is defined and item.type is string and item.type in (data["types"] | default({})) %}
{% if item.repeat is defined and item["repeat-expr"] is defined %}
  for _i = 1, {{item["repeat-expr"]}}_val do
    offset = parse_{{item.type}}(buffer, main, offset)
  end
{% else %}
  offset = parse_{{item.type}}(buffer, main, offset)
{% endif %}
{% else %}
  -- {{item.id}}: manual implementation needed
{% endif %}
{% endfor %}
end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add({{data.meta.tcp_port | default(0)}}, {{data.meta.id}}_proto)
