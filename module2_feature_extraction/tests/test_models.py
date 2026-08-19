import time
import pytest
from module2_feature_extraction.models import (
    PacketDirection,
    ConnectionState,
    FlowKey,
    FeatureVector,
)

def test_enums():
    assert PacketDirection.INBOUND.value == "INBOUND"
    assert PacketDirection.OUTBOUND.value == "OUTBOUND"
    assert PacketDirection.INTERNAL.value == "INTERNAL"
    assert PacketDirection.UNKNOWN.value == "UNKNOWN"

    assert ConnectionState.NEW.value == "NEW"
    assert ConnectionState.ESTABLISHED.value == "ESTABLISHED"
    assert ConnectionState.CLOSING.value == "CLOSING"
    assert ConnectionState.CLOSED.value == "CLOSED"
    assert ConnectionState.STATELESS.value == "STATELESS"
    assert ConnectionState.UNKNOWN.value == "UNKNOWN"

def test_flow_key():
    fk = FlowKey(
        endpoint_1_ip="10.0.0.1",
        endpoint_1_port=80,
        endpoint_2_ip="10.0.0.2",
        endpoint_2_port=54321,
        protocol="TCP"
    )
    assert fk.endpoint_1_ip == "10.0.0.1"
    assert "TCP:10.0.0.1:80<->10.0.0.2:54321" in str(fk)

def test_feature_vector_to_dict():
    now = time.time()
    fv = FeatureVector(
        src_ip="192.168.1.10",
        dst_ip="8.8.8.8",
        src_port=12345,
        dst_port=53,
        protocol="UDP",
        packet_length=70,
        timestamp=now,
        direction=PacketDirection.OUTBOUND,
        flow_id="test-flow-id",
        connection_state=ConnectionState.STATELESS,
        total_packets_in_flow=1,
        total_bytes=70,
    )
    d = fv.to_dict()
    assert d["src_ip"] == "192.168.1.10"
    assert d["direction"] == "OUTBOUND"
    assert d["connection_state"] == "STATELESS"
    assert "FeatureVector[" in str(fv)
