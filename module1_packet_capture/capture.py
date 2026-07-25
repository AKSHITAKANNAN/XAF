"""
capture.py
----------
Core Packet Capture Engine for the AI-Powered Explainable Adaptive Firewall.

This module is intentionally focused on ONE responsibility: sniffing live
traffic and turning raw packets into clean, validated PacketData objects
(see models.py). It does NOT do any threat scoring, blocking, or
visualization -- that belongs to other layers of the firewall (AI inference,
policy engine, dashboard, etc.), keeping this module reusable and testable
in isolation (clean architecture / separation of concerns).
"""

from typing import Callable, List, Optional

from scapy.all import sniff
from scapy.packet import Packet
from scapy.layers.inet import IP

from .models import PacketData, ProtocolType
from .utils import (
    build_logger,
    get_timestamp,
    is_packet_corrupted,
    detect_protocol,
    extract_ports,
)


class PacketCaptureEngine:
    """
    Captures live TCP/UDP/ICMP traffic from a network interface and converts
    each valid packet into a PacketData object for downstream AI processing.

    Typical usage:

        engine = PacketCaptureEngine(interface="eth0", on_packet=my_ai_pipeline.ingest)
        engine.start(packet_count=100)   # blocking; capture 100 packets

    Or, to just collect packets in memory:

        engine = PacketCaptureEngine(interface="eth0")
        engine.start(packet_count=50)
        packets = engine.get_captured_packets()
    """
    SUPPORTED_PROTOCOLS = {ProtocolType.TCP, ProtocolType.UDP, ProtocolType.ICMP}

    def __init__(
        self,
        interface: Optional[str] = None,
        bpf_filter: str = "tcp or udp or icmp",
        on_packet: Optional[Callable[[PacketData], None]] = None,
        log_level: int = None,
    ):
        """
        Initialize the capture engine.

        Args:
            interface: Network interface to sniff on (e.g. "eth0"). If None,
                Scapy will choose its default interface.
            bpf_filter: A Berkeley Packet Filter expression restricting
                capture to the protocols we care about. This reduces overhead
                by filtering at the kernel/libpcap level before packets ever
                reach Python.
            on_packet: Optional callback invoked with every successfully
                parsed PacketData object -- this is the hook the AI
                inference / explainability layer should use to receive
                packets in real time.
            log_level: Optional logging level override (defaults to INFO).
        """
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.on_packet = on_packet
        self._captured_packets: List[PacketData] = []

        import logging
        self.logger = build_logger(
            "packet_capture_engine.capture",
            level=log_level if log_level is not None else logging.INFO,
        )

    def start(self, packet_count: int = 0, timeout: Optional[int] = None) -> None:
        self.logger.info(
            "Starting capture on interface=%s filter='%s' count=%s timeout=%s",
            self.interface or "<default>", self.bpf_filter, packet_count, timeout,
        )
        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._handle_packet,
                store=False,          # we manage our own storage via PacketData
                count=packet_count,
                timeout=timeout,
            )
        except PermissionError:
            self.logger.error(
                "Permission denied while sniffing. Packet capture typically "
                "requires root/administrator privileges."
            )
            raise
        except Exception as exc:
            self.logger.error("Unexpected error during capture: %s", exc)
            raise

    def _handle_packet(self, raw_packet: Packet) -> None:
        if is_packet_corrupted(raw_packet):
            self.logger.debug("Dropped corrupted packet.")
            return

        packet_data = self._parse_packet(raw_packet)
        if packet_data is None:
            return

        self._captured_packets.append(packet_data)
        self.logger.debug("Captured packet: %s", packet_data)

        if self.on_packet is not None:
            try:
                self.on_packet(packet_data)
            except Exception as exc:
                self.logger.error("on_packet callback raised an exception: %s", exc)

    def _parse_packet(self, raw_packet: Packet) -> Optional[PacketData]:
        protocol = detect_protocol(raw_packet)
        if protocol not in self.SUPPORTED_PROTOCOLS:
            return None

        ip_layer = raw_packet[IP]
        src_port, dst_port = extract_ports(raw_packet)

        return PacketData(
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            length=len(raw_packet),
            timestamp=get_timestamp(),
        )

    def get_captured_packets(self) -> List[PacketData]:
        return list(self._captured_packets)

    def clear_captured_packets(self) -> None:
        self._captured_packets.clear()


if __name__ == "__main__":
    def _print_packet(pkt: PacketData) -> None:
        print(pkt)

    engine = PacketCaptureEngine(on_packet=_print_packet)
    engine.start(timeout=20)