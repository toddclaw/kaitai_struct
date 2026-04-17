meta:
  id: test_sample
  title: Test Sample Protocol
  endian: be
  tcp_port: 8001

seq:
  - id: magic
    contents: [0xDE, 0xAD]
  - id: version
    type: u1
  - id: length
    type: u2
  - id: payload
    size: length
