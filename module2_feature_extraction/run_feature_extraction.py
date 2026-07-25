"""
run_feature_extraction.py
----------------------------
Example / demo entry point showing how Module 2 (Feature Extraction Engine)
plugs into Module 1 (Packet Capture Engine) without modifying either.

TWO MODES:

1. live_capture_demo()
   Wires FeatureExtractionEngine directly into PacketCaptureEngine's
   on_packet callback for real, live traffic. Requires:
     - root/administrator privileges (raw socket access)
     - scapy installed
     - an actual network interface to sniff on
   This is what a real deployment would use.

2. simulated_demo()
   Uses hand-built PacketData objects (Module 1's own model) to exercise
   the full Module 2 pipeline -- flow tracking, rates, direction, TCP
   state -- without needing root access or live traffic. Useful for
   demos, CI environments, and sandboxes.

Run with:  python -m module2_feature_extraction.examples.run_feature_extraction
"""

import time

from module1_packet_capture.models import PacketData, ProtocolType
from module1_packet_capture.capture import PacketCaptureEngine

from module2_feature_extraction.feature_extractor import FeatureExtractionEngine


def live_capture_demo(packet_count: int = 20) -> None:
    """
    Capture real live traffic and print the resulting FeatureVector for
    each packet. Requires root/administrator privileges.

    Args:
        packet_count: Number of packets to capture before stopping.
    """
    engine = FeatureExtractionEngine()

    def on_packet(packet_data: PacketData) -> None:
        """Module 1's capture callback -> Module 2's extraction engine."""
        feature_vector = engine.extract(packet_data)
        print(feature_vector)

    capture = PacketCaptureEngine(on_packet=on_packet)
    capture.start(packet_count=packet_count)


def simulated_demo() -> None:
    """
    Run the Feature Extraction Engine against a small, synthetic sequence
    of packets representing one TCP handshake/session plus a couple of
    unrelated UDP/ICMP packets, so no live capture or root access is needed.
    """
    engine = FeatureExtractionEngine()
    now = time.time()

    synthetic_packets = [
        # A simple TCP handshake + data exchange between two endpoints.
        PacketData(src_ip="192.168.1.10", dst_ip="93.184.216.34",
                   src_port=54321, dst_port=443, protocol=ProtocolType.TCP,
                   length=60, timestamp=now, extra={"tcp_flags": "S", "ttl": 64}),
        PacketData(src_ip="93.184.216.34", dst_ip="192.168.1.10",
                   src_port=443, dst_port=54321, protocol=ProtocolType.TCP,
                   length=60, timestamp=now + 0.05, extra={"tcp_flags": "SA", "ttl": 55}),
        PacketData(src_ip="192.168.1.10", dst_ip="93.184.216.34",
                   src_port=54321, dst_port=443, protocol=ProtocolType.TCP,
                   length=1500, timestamp=now + 0.10, extra={"tcp_flags": "PA", "ttl": 64}),
        PacketData(src_ip="93.184.216.34", dst_ip="192.168.1.10",
                   src_port=443, dst_port=54321, protocol=ProtocolType.TCP,
                   length=1500, timestamp=now + 0.20, extra={"tcp_flags": "A", "ttl": 55}),

        # An unrelated UDP DNS lookup.
        PacketData(src_ip="192.168.1.10", dst_ip="8.8.8.8",
                   src_port=33445, dst_port=53, protocol=ProtocolType.UDP,
                   length=70, timestamp=now + 0.30),

        # An unrelated ICMP ping.
        PacketData(src_ip="192.168.1.10", dst_ip="8.8.4.4",
                   src_port=None, dst_port=None, protocol=ProtocolType.ICMP,
                   length=98, timestamp=now + 0.40),
    ]

    print("=== Simulated Feature Extraction Demo ===\n")
    for packet in synthetic_packets:
        feature_vector = engine.extract(packet)
        print(feature_vector)
        print(f"  direction={feature_vector.direction.value} "
              f"state={feature_vector.connection_state.value} "
              f"payload_size={feature_vector.payload_size} "
              f"packet_rate={feature_vector.packet_rate:.2f}/s "
              f"byte_rate={feature_vector.byte_rate:.2f}B/s "
              f"avg_flow_time={feature_vector.avg_flow_time:.3f}s\n")

    print(f"Active flows tracked: {engine.get_active_flow_count()}")


if __name__ == "__main__":
    # The simulated demo is the safe default -- it needs no root access and
    # works in any environment (including CI/sandboxes). Uncomment the line
    # below to run against real live traffic instead (requires root).
    #simulated_demo()
    live_capture_demo(packet_count=40)
