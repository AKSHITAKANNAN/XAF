"""
utils.py
--------
Stand-alone helper functions used by the Packet Capture Engine.

These are kept separate from capture.py so that they can be unit-tested in
isolation (no live network / Scapy sniffing required) and reused elsewhere
in the Adaptive Firewall codebase (e.g. by the AI feature-extraction module).
"""

import logging
import time
from typing import Optional

from scapy.packet import Packet
from scapy.layers.inet import IP, TCP, UDP, ICMP

from .models import ProtocolType


def build_logger(name: str = "packet_capture_engine", level: int = logging.INFO) -> logging.Logger:
    """
    Create (or fetch) a configured logger instance.

    Centralizing logger setup here means every module in the engine logs in
    a consistent format, and log level can be tuned in one place.

    Args:
        name: Logger name, typically the module name.
        level: Logging verbosity (e.g. logging.INFO, logging.DEBUG).

    Returns:
        A configured logging.Logger instance.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    logger.setLevel(level)
    return logger


def get_timestamp() -> float:
    """
    Return the current time as a Unix epoch timestamp (float seconds).

    Wrapped in its own function so timestamp generation can be mocked in
    tests, or later swapped for a monotonic/NTP-synced clock if needed.
    """
    return time.time()


def is_packet_corrupted(packet: Packet) -> bool:
    """
    Determine whether a captured packet is malformed/corrupted and should be
    discarded rather than passed on to the AI pipeline.

    A packet is treated as corrupted if:
      - It has no IP layer at all (we only care about IP traffic), or
      - Scapy raises an exception while trying to access basic layer fields
        (this can happen with truncated or malformed captures).

    Args:
        packet: The raw Scapy packet object.

    Returns:
        True if the packet should be dropped, False if it is safe to parse.
    """
    try:
        if not packet.haslayer(IP):
            return True

        ip_layer = packet[IP]

        # Touching these fields forces Scapy to validate the layer; if the
        # packet is truncated/corrupted this will raise, and we catch it below.
        _ = ip_layer.src
        _ = ip_layer.dst
        _ = len(packet)

        return False
    except Exception:
        # Any unexpected parsing error means we cannot trust this packet.
        return True


def detect_protocol(packet: Packet) -> ProtocolType:
    """
    Identify which transport-layer protocol a packet belongs to.

    Args:
        packet: The raw Scapy packet object (must contain an IP layer).

    Returns:
        A ProtocolType enum value (TCP, UDP, ICMP, or OTHER).
    """
    if packet.haslayer(TCP):
        return ProtocolType.TCP
    if packet.haslayer(UDP):
        return ProtocolType.UDP
    if packet.haslayer(ICMP):
        return ProtocolType.ICMP
    return ProtocolType.OTHER


def extract_ports(packet: Packet) -> "tuple[Optional[int], Optional[int]]":
    """
    Extract source and destination ports from a packet, if applicable.

    ICMP and other non-port-based protocols will simply return (None, None).

    Args:
        packet: The raw Scapy packet object.

    Returns:
        A tuple of (source_port, destination_port).
    """
    if packet.haslayer(TCP):
        layer = packet[TCP]
        return layer.sport, layer.dport
    if packet.haslayer(UDP):
        layer = packet[UDP]
        return layer.sport, layer.dport
    return None, None
