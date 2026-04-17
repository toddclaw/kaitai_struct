meta:
  id: my_protocol
  title: My Test Protocol
  endian: be
  tcp_port: 8002

seq:
  - id: magic
    contents: [0xAB, 0xCD]
  - id: version
    type: u1
  - id: msg_type
    type: u1
  - id: record_count
    type: u2
  - id: records
    type: record
    repeat: expr
    repeat-expr: record_count

types:
  record:
    seq:
      - id: record_type
        type: u1
      - id: record_length
        type: u1
      - id: record_data
        size: record_length
