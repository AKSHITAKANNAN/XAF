"""
utils.py (Module 2)
--------------------
Stand-alone helper functions for the Feature Extraction Engine.

WHY THIS FILE EXISTS
Pure functions with no class state are the easiest thing in the codebase
to unit test and reuse. Keeping them here (rather than as private methods
buried in flow_builder.py / feature_extractor.py) means they can be tested
directly and reused if Module 3 ever needs the same logic (e.g. direction
detection for its own diagnostics).

USED BY
- flow_builder.py       (generate_flow_id, map_tcp_flags_to_state)
- feature_extractor.py  (compute_flow_key, determine_direction, safe_get_extra)
"""

import hashlib
import ipaddress
from typing import Any, Optional

from module2_feature_extraction.models import FlowKey, PacketDirection, ConnectionState


def compute_flow_key(src_ip: str, src_port: Optional[int], dst_ip: str,
                      dst_port: Optional[int], protocol: str) -> FlowKey:
    """
    Build a direction-independent FlowKey for a packet's 5-tuple.

    Ports default to 0 when None (e.g. ICMP has no ports) so the sort
    comparison below always has well-defined integer values to compare.

    Args:
        src_ip: Packet source IP address.
        src_port: Packet source port, or None if not applicable.
        dst_ip: Packet destination IP address.
        dst_port: Packet destination port, or None if not applicable.
        protocol: Transport protocol string (e.g. "TCP").

    Returns:
        A FlowKey identical for both directions of the same conversation.
    """
    endpoint_a = (src_ip, src_port or 0)
    endpoint_b = (dst_ip, dst_port or 0)

    # Sort so that request and reply packets resolve to the same key,
    # regardless of which endpoint happened to send this particular packet.
    if endpoint_a <= endpoint_b:
        lo, hi = endpoint_a, endpoint_b
    else:
        lo, hi = endpoint_b, endpoint_a

    return FlowKey(
        endpoint_1_ip=lo[0], endpoint_1_port=lo[1],
        endpoint_2_ip=hi[0], endpoint_2_port=hi[1],
        protocol=protocol,
    )


def generate_flow_id(flow_key: FlowKey) -> str:
    """
    Derive a short, stable, human-shareable identifier for a FlowKey.

    A SHA-256 hash (truncated) is used instead of the raw tuple so flow IDs
    are fixed-length strings safe to use as dictionary keys, log fields, or
    a categorical feature for the AI model, without leaking the ability to
    trivially reverse-engineer IPs/ports from the string alone.

    Args:
        flow_key: The canonical FlowKey to derive an ID for.

    Returns:
        A 16-character hex string uniquely identifying the flow.
    """
    raw = str(flow_key).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def determine_direction(src_ip: str, dst_ip: str, home_networks: list) -> PacketDirection:
    """
    Classify a packet's direction relative to the configured home networks.

    Args:
        src_ip: Packet source IP address.
        dst_ip: Packet destination IP address.
        home_networks: List of CIDR strings considered "internal"
            (see config.FeatureExtractionConfig.home_networks).

    Returns:
        PacketDirection.OUTBOUND if src is internal and dst is external,
        PacketDirection.INBOUND if src is external and dst is internal,
        PacketDirection.INTERNAL if both are internal,
        PacketDirection.UNKNOWN if addresses can't be parsed or both are
        external (i.e. this traffic doesn't touch the home network at all).
    """
    try:
        networks = [ipaddress.ip_network(net, strict=False) for net in home_networks]
        src_addr = ipaddress.ip_address(src_ip)
        dst_addr = ipaddress.ip_address(dst_ip)
    except ValueError:
        # Malformed/unparseable IP (shouldn't normally happen since
        # Module 1 already validates packets, but we never trust input blindly).
        return PacketDirection.UNKNOWN

    src_is_home = any(src_addr in net for net in networks)
    dst_is_home = any(dst_addr in net for net in networks)

    if src_is_home and dst_is_home:
        return PacketDirection.INTERNAL
    if src_is_home and not dst_is_home:
        return PacketDirection.OUTBOUND
    if not src_is_home and dst_is_home:
        return PacketDirection.INBOUND
    return PacketDirection.UNKNOWN


def map_tcp_flags_to_state(tcp_flags: Optional[str], protocol: str) -> ConnectionState:
    """
    Translate raw TCP flag characters into a simplified ConnectionState.

    Args:
        tcp_flags: Scapy-style flag string (e.g. "S", "SA", "PA", "FA", "R"),
            or None if unavailable / not a TCP packet.
        protocol: Transport protocol string, used to short-circuit non-TCP
            protocols straight to STATELESS.

    Returns:
        A ConnectionState best describing this single packet's role in the
        connection lifecycle. Note this is a per-packet classification, not
        a full stateful reconstruction of the TCP state machine (that level
        of detail is intentionally left to Module 3 / the AI layer, which
        can look at the sequence of states across a flow).
    """
    if protocol != "TCP":
        return ConnectionState.STATELESS

    if not tcp_flags:
        return ConnectionState.UNKNOWN

    flags = tcp_flags.upper()

    if "R" in flags:
        return ConnectionState.CLOSED
    if "F" in flags:
        return ConnectionState.CLOSING
    if flags == "S":
        return ConnectionState.NEW
    if "S" in flags and "A" in flags:
        return ConnectionState.ESTABLISHED
    if "A" in flags or "P" in flags:
        return ConnectionState.ESTABLISHED

    return ConnectionState.UNKNOWN


def safe_get_extra(extra: dict, key: str, default: Any = None) -> Any:
    """
    Defensively read a value out of PacketData.extra without raising.

    Module 1's PacketData.extra is an open-ended dict that may or may not
    contain enrichment fields like 'ttl', 'tcp_flags', or 'window_size'
    depending on the capture-side implementation. This helper isolates
    that uncertainty in one place instead of scattering `.get()` calls
    (and their default values) throughout feature_extractor.py.

    Args:
        extra: The PacketData.extra dictionary (may be empty).
        key: The field name to look up.
        default: Value to return if the key is absent or extra is falsy.

    Returns:
        The value if present, otherwise `default`.
    """
    if not extra:
        return default
    return extra.get(key, default)


def estimate_payload_size(packet_length: int, protocol: str) -> int:
    """
    Estimate the application-layer payload size when the exact value is not
    available from Module 1.

    Module 1's PacketData only exposes total packet length, not a
    pre-computed payload size, so this approximates it by subtracting
    typical header sizes for a standard IPv4 packet. This is a best-effort
    estimate, not an exact measurement -- see README_MODULE2.md for the
    optional Module 1 enhancement that would make this exact.

    Args:
        packet_length: Total captured packet length in bytes.
        protocol: Transport protocol string ("TCP", "UDP", "ICMP", "OTHER").

    Returns:
        Estimated payload size in bytes (never negative).
    """
    ip_header = 20  # Typical (no-options) IPv4 header size.
    transport_header = {
        "TCP": 20,   # Typical (no-options) TCP header size.
        "UDP": 8,    # Fixed UDP header size.
        "ICMP": 8,   # Typical ICMP echo header size.
    }.get(protocol, 0)

    payload = packet_length - ip_header - transport_header
    return max(payload, 0)
