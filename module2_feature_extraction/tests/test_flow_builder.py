import pytest
from module2_feature_extraction.models import FlowKey, ConnectionState
from module2_feature_extraction.flow_builder import FlowBuilder, FlowRecord

def test_flow_builder_lifecycle():
    builder = FlowBuilder()
    fk = FlowKey("192.168.1.10", 1234, "10.0.0.1", 80, "TCP")
    rec = builder.create_flow(fk, "flow-123", 100.0, "192.168.1.10")
    
    assert rec.total_packets == 0
    assert rec.total_bytes == 0

    # First packet
    iat1 = builder.update_with_packet(rec, packet_length=100, timestamp=100.0, protocol="TCP", tcp_flags="S")
    assert iat1 == 0.0
    assert rec.total_packets == 1
    assert rec.total_bytes == 100
    assert rec.connection_state == ConnectionState.NEW

    # Second packet (0.5s later)
    iat2 = builder.update_with_packet(rec, packet_length=200, timestamp=100.5, protocol="TCP", tcp_flags="SA")
    assert iat2 == 0.5
    assert rec.total_packets == 2
    assert rec.total_bytes == 300
    assert rec.duration() == 0.5
    assert rec.avg_packet_size() == 150.0
    assert rec.packet_rate() == 4.0   # 2 / 0.5 = 4.0
    assert rec.byte_rate() == 600.0   # 300 / 0.5 = 600.0
    assert rec.connection_state == ConnectionState.ESTABLISHED
