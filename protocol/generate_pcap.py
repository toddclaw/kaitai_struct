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

src_mac = "00:00:00:00:00:01"
dst_mac = "00:00:00:00:00:02"
src_ip  = "192.168.1.1"
dst_ip  = "192.168.1.2"
sport   = 54321
dport   = 8002

def pkt(seq, ack, flags, payload=b""):
    p = (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=src_ip, dst=dst_ip)
        / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
    )
    if payload:
        p = p / Raw(load=payload)
    return p

packets = [
    pkt(1000, 0,    "S"),
    pkt(2000, 1001, "SA"),
    pkt(1001, 2001, "A"),
    pkt(1001,            2001, "PA", msg1),
    pkt(1001 + len(msg1), 2001, "PA", msg2),
    pkt(1001 + len(msg1) + len(msg2), 2001, "PA", msg3),
]

out = "protocol/my_protocol.pcap"
wrpcap(out, packets)
print(f"Written {len(packets)} packets to {out}")
print(f"  msg1: {len(msg1)} bytes, {3} records")
print(f"  msg2: {len(msg2)} bytes, {3} records")
print(f"  msg3: {len(msg3)} bytes, {1} record")
