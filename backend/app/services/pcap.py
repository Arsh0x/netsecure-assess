from __future__ import annotations

import hashlib
import ipaddress
import struct
from collections import defaultdict
from typing import Any


class CaptureError(ValueError):
    pass


def _anonymize(address: str) -> str:
    digest = hashlib.sha256(address.encode()).digest()
    return f"10.255.{digest[0]}.{digest[1]}"


def _packet_metadata(packet: bytes, link_type: int = 1) -> dict[str, Any] | None:
    offset = 14 if link_type == 1 else 0
    if len(packet) < offset + 20 or (link_type == 1 and packet[12:14] != b"\x08\x00"):
        return None
    ip = packet[offset:]
    if ip[0] >> 4 != 4:
        return None
    header_len = (ip[0] & 0x0F) * 4
    if header_len < 20 or len(ip) < header_len:
        return None
    protocol_number = ip[9]
    source, destination = str(ipaddress.ip_address(ip[12:16])), str(ipaddress.ip_address(ip[16:20]))
    source_port = destination_port = None
    if protocol_number in {6, 17} and len(ip) >= header_len + 4:
        source_port, destination_port = struct.unpack("!HH", ip[header_len:header_len + 4])
    protocol = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(protocol_number, f"IP-{protocol_number}")
    return {"source":source,"destination":destination,"source_port":source_port,"destination_port":destination_port,"protocol":protocol,"bytes":len(packet)}


def parse_capture(data: bytes, anonymize: bool = True, max_packets: int = 100_000) -> list[dict[str, Any]]:
    if len(data) < 24:
        raise CaptureError("Capture file is too small")
    packets: list[dict[str, Any]] = []
    magic = data[:4]
    if magic in {b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"}:
        endian = "<"
    elif magic in {b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"}:
        endian = ">"
    elif magic == b"\x0a\x0d\x0d\x0a":
        return _aggregate(_parse_pcapng(data, max_packets), anonymize)
    else:
        raise CaptureError("Only PCAP and PCAPNG files are supported")
    try:
        link_type = struct.unpack(endian + "I", data[20:24])[0]
    except struct.error as exc:
        raise CaptureError("Invalid PCAP header") from exc
    if link_type not in {1, 101}:
        raise CaptureError("Only Ethernet and raw IPv4 captures are supported")
    offset = 24
    while offset + 16 <= len(data) and len(packets) < max_packets:
        _, _, captured_len, _ = struct.unpack(endian + "IIII", data[offset:offset + 16])
        offset += 16
        if captured_len > 262_144 or offset + captured_len > len(data):
            raise CaptureError("Malformed or oversized packet record")
        item = _packet_metadata(data[offset:offset + captured_len], link_type)
        if item:
            packets.append(item)
        offset += captured_len
    return _aggregate(packets, anonymize)


def _parse_pcapng(data: bytes, max_packets: int) -> list[dict[str, Any]]:
    offset = 0
    packets: list[dict[str, Any]] = []
    while offset + 12 <= len(data) and len(packets) < max_packets:
        block_type, block_len = struct.unpack("<II", data[offset:offset + 8])
        if block_len < 12 or block_len > 4_194_304 or offset + block_len > len(data):
            raise CaptureError("Malformed PCAPNG block")
        if block_type == 6 and block_len >= 32:
            captured_len = struct.unpack("<I", data[offset + 20:offset + 24])[0]
            if captured_len <= 262_144 and offset + 28 + captured_len <= offset + block_len:
                item = _packet_metadata(data[offset + 28:offset + 28 + captured_len], 1)
                if item:
                    packets.append(item)
        offset += block_len
    return packets


def _aggregate(packets: list[dict[str, Any]], anonymize: bool) -> list[dict[str, Any]]:
    grouped: dict[tuple, dict[str, Any]] = defaultdict(lambda:{"packets":0,"bytes":0})
    for packet in packets:
        source = _anonymize(packet["source"]) if anonymize else packet["source"]
        destination = _anonymize(packet["destination"]) if anonymize else packet["destination"]
        key = (source,destination,packet["source_port"],packet["destination_port"],packet["protocol"])
        grouped[key]["packets"] += 1
        grouped[key]["bytes"] += packet["bytes"]
    return [{"source":key[0],"destination":key[1],"source_port":key[2],"destination_port":key[3],"protocol":key[4],**value} for key,value in grouped.items()]

