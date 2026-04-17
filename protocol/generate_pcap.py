#!/usr/bin/env python3
"""Generate a synthetic pcap for my_protocol.ksy testing."""
import struct
import sys

try:
    from scapy.all import Ether, IP, TCP, Raw, wrpcap
except ImportError:
    print("scapy not found. Install with: pip3 install scapy", file=sys.stderr)
    sys.exit(1)


def make_record(record_type: int, data: bytes) -> bytes:
    return struct.pack("BB", record_type, len(data)) + data


def make_message(version: int, msg_type: int, records: list[bytes]) -> bytes:
    record_count = len(records)
    header = b"\xAB\xCD" + struct.pack("!BBH", version, msg_type, record_count)
    return header + b"".join(records)


msg1 = make_message(1, 0x01, [
    make_record(1, b"hello"),
    make_record(2, b"\x01\x02\x03"),
    make_record(3, b"world"),
])

msg2 = make_message(1, 0x02, [
    make_record(1, b"test"),
    make_record(4, b"\xFF\xFE"),
    make_record(5, b"bye"),
])

msg3 = make_message(2, 0x03, [
    make_record(10, b"ping"),
])

cli_mac = "00:00:00:00:00:01"
srv_mac = "00:00:00:00:00:02"
cli_ip  = "192.168.1.1"
srv_ip  = "192.168.1.2"
cli_port = 54321
srv_port = 8002

def cli2srv(seq, ack, flags, payload=b""):
    p = (Ether(src=cli_mac, dst=srv_mac)
         / IP(src=cli_ip, dst=srv_ip)
         / TCP(sport=cli_port, dport=srv_port, flags=flags, seq=seq, ack=ack))
    return p / Raw(load=payload) if payload else p

def srv2cli(seq, ack, flags, payload=b""):
    p = (Ether(src=srv_mac, dst=cli_mac)
         / IP(src=srv_ip, dst=cli_ip)
         / TCP(sport=srv_port, dport=cli_port, flags=flags, seq=seq, ack=ack))
    return p / Raw(load=payload) if payload else p

cli_seq = 1000
srv_seq = 2000

off = cli_seq + 1
packets = [
    cli2srv(cli_seq,        0,           "S"),          # SYN
    srv2cli(srv_seq,        cli_seq + 1, "SA"),         # SYN-ACK
    cli2srv(cli_seq + 1,    srv_seq + 1, "A"),          # ACK
    cli2srv(off,            srv_seq + 1, "PA", msg1),   # data 1
    cli2srv(off + len(msg1),srv_seq + 1, "PA", msg2),   # data 2
    cli2srv(off + len(msg1) + len(msg2), srv_seq + 1, "PA", msg3),  # data 3
]

out = "protocol/my_protocol.pcap"
wrpcap(out, packets)
print(f"Written {len(packets)} packets to {out}")
print(f"  msg1: {len(msg1)} bytes, 3 records")
print(f"  msg2: {len(msg2)} bytes, 3 records")
print(f"  msg3: {len(msg3)} bytes, 1 record")
