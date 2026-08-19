import pytest
from module2_feature_extraction.utils import (
    compute_flow_key,
    generate_flow_id,
    determine_direction,
    map_tcp_flags_to_state,
    safe_get_extra,
    estimate_payload_size,
)
from module2_feature_extraction.models import PacketDirection, ConnectionState

def test_compute_flow_key_symmetry():
    k1 = compute_flow_key("192.168.1.10", 54321, "93.184.216.34", 443, "TCP")
    k2 = compute_flow_key("93.184.216.34", 443, "192.168.1.10", 54321, "TCP")
    assert k1 == k2
    assert generate_flow_id(k1) == generate_flow_id(k2)

def test_determine_direction():
    home_nets = ["192.168.0.0/16", "10.0.0.0/8"]
    
    assert determine_direction("192.168.1.5", "8.8.8.8", home_nets) == PacketDirection.OUTBOUND
    assert determine_direction("8.8.8.8", "192.168.1.5", home_nets) == PacketDirection.INBOUND
    assert determine_direction("192.168.1.5", "10.0.0.1", home_nets) == PacketDirection.INTERNAL
    assert determine_direction("8.8.8.8", "1.1.1.1", home_nets) == PacketDirection.UNKNOWN
    assert determine_direction("invalid_ip", "8.8.8.8", home_nets) == PacketDirection.UNKNOWN

def test_map_tcp_flags_to_state():
    assert map_tcp_flags_to_state("S", "TCP") == ConnectionState.NEW
    assert map_tcp_flags_to_state("SA", "TCP") == ConnectionState.ESTABLISHED
    assert map_tcp_flags_to_state("PA", "TCP") == ConnectionState.ESTABLISHED
    assert map_tcp_flags_to_state("FA", "TCP") == ConnectionState.CLOSING
    assert map_tcp_flags_to_state("R", "TCP") == ConnectionState.CLOSED
    assert map_tcp_flags_to_state(None, "UDP") == ConnectionState.STATELESS

def test_safe_get_extra():
    d = {"ttl": 64}
    assert safe_get_extra(d, "ttl") == 64
    assert safe_get_extra(d, "missing", default=100) == 100
    assert safe_get_extra({}, "ttl", default=None) is None

def test_estimate_payload_size():
    assert estimate_payload_size(100, "TCP") == 60  # 100 - 20 - 20 = 60
    assert estimate_payload_size(100, "UDP") == 72  # 100 - 20 - 8 = 72
    assert estimate_payload_size(20, "TCP") == 0    # non-negative
