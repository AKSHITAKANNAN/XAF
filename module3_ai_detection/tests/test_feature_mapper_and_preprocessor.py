import time
import pytest
import numpy as np
from module2_feature_extraction.models import FeatureVector, PacketDirection, ConnectionState
from module3_ai_detection.feature_mapper import FeatureMapper, FEATURE_ORDER
from module3_ai_detection.preprocessor import Preprocessor
from module3_ai_detection.exceptions import InvalidFeatureVectorError, FeatureMappingError

def test_feature_mapper_mapping():
    now = time.time()
    fv = FeatureVector(
        src_ip="192.168.1.10", dst_ip="8.8.8.8", src_port=1234, dst_port=53,
        protocol="UDP", packet_length=100, timestamp=now, ttl=64,
        direction=PacketDirection.OUTBOUND, connection_state=ConnectionState.STATELESS,
        total_packets_in_flow=1, total_bytes=100
    )
    
    mapper = FeatureMapper()
    raw = mapper.map(fv)
    assert raw["packet_length"] == 100.0
    assert raw["protocol"] == "UDP"
    assert raw["direction"] == "OUTBOUND"
    assert raw["connection_state"] == "STATELESS"
    assert set(raw.keys()) == set(FEATURE_ORDER)

def test_feature_mapper_invalid():
    mapper = FeatureMapper()
    with pytest.raises(InvalidFeatureVectorError):
        mapper.map(None)

def test_preprocessor_transform():
    prep = Preprocessor()
    raw = {
        "packet_length": 100, "flow_duration": 1.0, "packet_rate": 1.0,
        "byte_rate": 100.0, "payload_size": 72, "avg_packet_size": 100.0,
        "total_packets_in_flow": 1, "total_bytes": 100, "inter_arrival_time": 0.0,
        "ttl": 64, "window_size": 0, "avg_flow_time": 1.0,
        "protocol": "UDP", "direction": "OUTBOUND", "connection_state": "STATELESS"
    }
    
    arr = prep.transform(raw)
    assert isinstance(arr, np.ndarray)
    assert arr.shape == (1, len(FEATURE_ORDER))
    
    # Check batch transform
    batch_arr = prep.transform_batch([raw, raw])
    assert batch_arr.shape == (2, len(FEATURE_ORDER))
