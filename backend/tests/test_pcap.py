import socket
import struct

from app.services.pcap import parse_capture


def test_pcap_is_reduced_to_anonymized_metadata():
    ethernet = b"\x00" * 12 + b"\x08\x00"
    ipv4 = bytes([0x45,0,0,40,0,0,0,0,64,6,0,0]) + socket.inet_aton("192.168.1.10") + socket.inet_aton("192.168.1.20")
    tcp = struct.pack("!HH", 51515, 443) + b"\x00" * 16
    packet = ethernet + ipv4 + tcp
    global_header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII",2,4,0,0,65535,1)
    record_header = struct.pack("<IIII",0,0,len(packet),len(packet))
    rows = parse_capture(global_header + record_header + packet, anonymize=True)
    assert rows[0]["protocol"] == "TCP"
    assert rows[0]["destination_port"] == 443
    assert rows[0]["source"].startswith("10.255.")
    assert "payload" not in rows[0]

