import time
import pytest
from module1_packet_capture.models import ProtocolType, PacketData

def test_protocol_type_values():
    assert ProtocolType.TCP.value == "TCP"
    assert ProtocolType.UDP.value == "UDP"
    assert ProtocolType.ICMP.value == "ICMP"
    assert ProtocolType.OTHER.value == "OTHER"

def test_packet_data_creation_and_to_dict():
    now = time.time()
    packet = PacketData(
        src_ip="192.168.1.1",
        dst_ip="192.168.1.2",
        protocol=ProtocolType.TCP,
        length=64,
        timestamp=now,
        src_port=12345,
        dst_port=80,
        extra={"ttl": 64}
    )
    
    assert packet.src_ip == "192.168.1.1"
    assert packet.dst_ip == "192.168.1.2"
    assert packet.protocol == ProtocolType.TCP
    assert packet.length == 64
    assert packet.timestamp == now
    assert packet.src_port == 12345
    assert packet.dst_port == 80
    assert packet.extra == {"ttl": 64}

    d = packet.to_dict()
    assert d["src_ip"] == "192.168.1.1"
    assert d["protocol"] == "TCP"
    assert d["extra"]["ttl"] == 64
    assert "[TCP]" in str(packet)
