import time
import pytest
from module1_packet_capture.models import PacketData, ProtocolType
from module2_feature_extraction.feature_extractor import FeatureExtractionEngine, FeatureExtractionError
from module2_feature_extraction.models import PacketDirection, ConnectionState

def test_feature_extractor_single_packet():
    engine = FeatureExtractionEngine()
    now = time.time()
    packet = PacketData(
        src_ip="192.168.1.10",
        dst_ip="8.8.8.8",
        src_port=54321,
        dst_port=53,
        protocol=ProtocolType.UDP,
        length=70,
        timestamp=now
    )
    
    fv = engine.extract(packet)
    assert fv.src_ip == "192.168.1.10"
    assert fv.dst_ip == "8.8.8.8"
    assert fv.protocol == "UDP"
    assert fv.direction == PacketDirection.OUTBOUND
    assert fv.connection_state == ConnectionState.STATELESS
    assert fv.total_packets_in_flow == 1
    assert fv.inter_arrival_time is None

def test_feature_extractor_flow_accumulation():
    engine = FeatureExtractionEngine()
    now = time.time()
    
    pkt1 = PacketData(
        src_ip="192.168.1.10", dst_ip="93.184.216.34", src_port=54321, dst_port=443,
        protocol=ProtocolType.TCP, length=60, timestamp=now, extra={"tcp_flags": "S"}
    )
    pkt2 = PacketData(
        src_ip="93.184.216.34", dst_ip="192.168.1.10", src_port=443, dst_port=54321,
        protocol=ProtocolType.TCP, length=60, timestamp=now + 0.1, extra={"tcp_flags": "SA"}
    )
    
    fv1 = engine.extract(pkt1)
    fv2 = engine.extract(pkt2)
    
    assert fv1.flow_id == fv2.flow_id
    assert fv1.connection_state == ConnectionState.NEW
    assert fv2.connection_state == ConnectionState.ESTABLISHED
    assert fv2.total_packets_in_flow == 2
    assert fv2.inter_arrival_time == pytest.approx(0.1)

def test_feature_extractor_error_handling():
    engine = FeatureExtractionEngine()
    with pytest.raises(FeatureExtractionError):
        engine.extract(None)
