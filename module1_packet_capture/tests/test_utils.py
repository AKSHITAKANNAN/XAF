import time
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Packet

from module1_packet_capture.utils import (
    build_logger,
    get_timestamp,
    is_packet_corrupted,
    detect_protocol,
    extract_ports,
)
from module1_packet_capture.models import ProtocolType

def test_build_logger():
    logger = build_logger("test_logger")
    assert logger.name == "test_logger"
    assert len(logger.handlers) > 0

def test_get_timestamp():
    ts = get_timestamp()
    assert isinstance(ts, float)
    assert ts > 0

def test_detect_protocol_and_extract_ports():
    tcp_pkt = IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=1234, dport=80)
    udp_pkt = IP(src="10.0.0.1", dst="10.0.0.2")/UDP(sport=5353, dport=53)
    icmp_pkt = IP(src="10.0.0.1", dst="10.0.0.2")/ICMP()

    assert detect_protocol(tcp_pkt) == ProtocolType.TCP
    assert extract_ports(tcp_pkt) == (1234, 80)

    assert detect_protocol(udp_pkt) == ProtocolType.UDP
    assert extract_ports(udp_pkt) == (5353, 53)

    assert detect_protocol(icmp_pkt) == ProtocolType.ICMP
    assert extract_ports(icmp_pkt) == (None, None)

def test_is_packet_corrupted():
    tcp_pkt = IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=1234, dport=80)
    assert not is_packet_corrupted(tcp_pkt)

    raw_pkt = Packet(b"invalid raw data")
    assert is_packet_corrupted(raw_pkt)
