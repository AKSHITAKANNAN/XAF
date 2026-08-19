import time
import pytest
from module2_feature_extraction.config import FeatureExtractionConfig
from module2_feature_extraction.models import FlowKey
from module2_feature_extraction.session_manager import SessionManager

def test_session_manager_get_or_create_and_expiry():
    config = FeatureExtractionConfig(
        flow_timeout_seconds=2.0,
        max_tracked_flows=10,
        cleanup_interval_seconds=1.0
    )
    sm = SessionManager(config=config)
    
    fk = FlowKey("192.168.1.10", 1234, "10.0.0.1", 80, "TCP")
    rec1 = sm.get_or_create_flow(fk, "flow-1", timestamp=100.0, src_ip="192.168.1.10")
    assert sm.get_active_flow_count() == 1
    
    rec2 = sm.get_or_create_flow(fk, "flow-1", timestamp=101.0, src_ip="192.168.1.10")
    assert rec1 is rec2
    assert sm.get_active_flow_count() == 1

    # Expiry test
    expired = sm.cleanup_expired_flows(now=104.0)
    assert expired == 1
    assert sm.get_active_flow_count() == 0

def test_session_manager_capacity_eviction():
    config = FeatureExtractionConfig(
        max_tracked_flows=2
    )
    sm = SessionManager(config=config)
    
    fk1 = FlowKey("10.0.0.1", 1, "10.0.0.2", 80, "TCP")
    fk2 = FlowKey("10.0.0.1", 2, "10.0.0.2", 80, "TCP")
    fk3 = FlowKey("10.0.0.1", 3, "10.0.0.2", 80, "TCP")
    
    sm.get_or_create_flow(fk1, "flow-1", timestamp=100.0, src_ip="10.0.0.1")
    sm.get_or_create_flow(fk2, "flow-2", timestamp=101.0, src_ip="10.0.0.1")
    assert sm.get_active_flow_count() == 2

    # Triggers eviction of oldest flow (fk1)
    sm.get_or_create_flow(fk3, "flow-3", timestamp=102.0, src_ip="10.0.0.1")
    assert sm.get_active_flow_count() == 2
