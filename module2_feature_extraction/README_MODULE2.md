# XAF — Module 2: Feature Extraction Engine

Converts live `PacketData` objects from **Module 1 (Packet Capture Engine)**
into AI-ready `FeatureVector` objects for **Module 3 (AI Detection Engine)**.

This module performs **feature extraction only** — no IDS/IPS logic, no AI
inference, no firewall blocking, no dashboard.

---

## 1. Folder Structure

```
xaf_firewall/
├── module1_packet_capture/          # Module 1 — UNCHANGED
│   ├── __init__.py                  # NEW FILE — see Integration Notes
│   ├── capture.py                   # original, byte-for-byte unchanged
│   ├── models.py                    # original, byte-for-byte unchanged
│   └── utils.py                     # original, byte-for-byte unchanged
│
├── module2_feature_extraction/       # Module 2 — NEW
│   ├── __init__.py
│   ├── config.py
│   ├── logger.py
│   ├── models.py
│   ├── utils.py
│   ├── flow_builder.py
│   ├── session_manager.py
│   ├── feature_extractor.py
│   ├── tests/
│   │   ├── __init__.py
│   │   ├── test_models.py
│   │   ├── test_utils.py
│   │   ├── test_flow_builder.py
│   │   ├── test_session_manager.py
│   │   └── test_feature_extractor.py
│   └── examples/
│       ├── __init__.py
│       └── run_feature_extraction.py
│
└── README_MODULE2.md                 # this file
```

---

## 2. File-by-File Explanation

| File | Why it exists | What it does | Used by |
|---|---|---|---|
| `config.py` | Separates tunable policy from mechanism (clean architecture) | Defines `FeatureExtractionConfig`: home networks, flow timeout, max tracked flows, cleanup interval | `session_manager.py`, `feature_extractor.py` |
| `logger.py` | Consistent logging without depending on Module 1's logger | Provides `get_logger()` — one stream handler, no duplicate handlers | `flow_builder.py`, `session_manager.py`, `feature_extractor.py` |
| `models.py` | Entities layer — plain data, no I/O | `FeatureVector` (the output contract), `FlowKey`, `PacketDirection`, `ConnectionState` | Every other Module 2 file |
| `utils.py` | Pure, independently testable helper functions | `compute_flow_key` (direction-independent 5-tuple), `generate_flow_id`, `determine_direction`, `map_tcp_flags_to_state`, `safe_get_extra`, `estimate_payload_size` | `flow_builder.py`, `feature_extractor.py` |
| `flow_builder.py` | Single responsibility: update ONE flow's running stats | `FlowRecord` (mutable accumulator) + `FlowBuilder` (creates/updates records; computes duration, avg size, rates) | `session_manager.py` |
| `session_manager.py` | Single responsibility: own the flow *table* lifecycle | `SessionManager` — thread-safe dict of active flows, expiry, aggregate avg-flow-time statistic, capacity eviction | `feature_extractor.py` |
| `feature_extractor.py` | The "use case" / orchestration layer | `FeatureExtractionEngine.extract(packet_data) -> FeatureVector`; the **only** class other code needs to call | Module 1's `on_packet` callback, Module 3, example runner |
| `examples/run_feature_extraction.py` | Demonstrates real integration | `live_capture_demo()` (real traffic, needs root) and `simulated_demo()` (synthetic packets, no root needed) | Manual run / demo |
| `tests/*.py` | Prove correctness in isolation and end-to-end | Unit tests for every class above, plus integration tests using real Module 1 `PacketData` objects | CI / manual verification |

---

## 3. Integration Notes — Module 1

**No line of Module 1's original `capture.py`, `models.py`, or `utils.py` was
modified.** Checksums were verified identical before and after this build.

Two small, additive integration accommodations were required:

1. **`module1_packet_capture/__init__.py` (new file).**
   Module 1 was originally delivered as flat standalone files. This new
   `__init__.py` does two things, both purely additive:
   - Inserts Module 1's own directory onto `sys.path`, so `capture.py`'s
     original internal import (`from models import PacketData, ProtocolType`)
     keeps resolving correctly now that Module 1 lives inside a larger
     project package.
   - Re-exports `PacketData`, `ProtocolType`, `PacketCaptureEngine` for
     convenient `from module1_packet_capture import ...` usage.

2. **Optional (not required) future enhancement to `capture.py`.**
   Module 1's `PacketData.extra` dict is already designed as an open
   extension point. Module 2 reads `ttl`, `tcp_flags`, and `window_size`
   from `extra` when present, and **degrades gracefully to `None`** when
   they are not (see `test_extract_gracefully_handles_missing_extra_fields`).
   If richer packet-level features are desired later, Module 1's
   `_parse_packet()` could optionally populate `extra` like this:

   ```python
   # OPTIONAL — not applied, shown for future reference only:
   extra = {}
   if ip_layer.haslayer(TCP):
       extra["tcp_flags"] = str(raw_packet[TCP].flags)
       extra["window_size"] = raw_packet[TCP].window
   extra["ttl"] = ip_layer.ttl
   ```

   This is a **suggestion only** — Module 2 works correctly against the
   current, unmodified Module 1 output.

---

## 4. How Flows Are Identified

A "flow" is a conversation between two endpoints, independent of which side
sent a given packet. `compute_flow_key()` sorts the two `(ip, port)` pairs
so that a request and its reply always resolve to the **same** `FlowKey`
(verified by `test_flow_key_is_symmetric_for_request_and_reply` and
`test_extract_reply_packet_maps_to_same_flow_id`).

---

## 5. How To Run

### Install dependencies
```bash
pip install scapy pytest --break-system-packages
```

### Run the simulated demo (no root required)
```bash
cd xaf_firewall
python3 -m module2_feature_extraction.examples.run_feature_extraction
```

**Expected output:** six `FeatureVector` lines — a 4-packet TCP handshake
(flow ID stays constant across all 4, direction alternates
OUTBOUND/INBOUND, connection state progresses NEW → ESTABLISHED), followed
by one UDP and one ICMP packet, each with their own STATELESS flow. Ends
with `Active flows tracked: 3`.

### Run the live capture demo (requires root)
Edit `run_feature_extraction.py`, comment out `simulated_demo()` and
uncomment `live_capture_demo(packet_count=20)`, then:
```bash
sudo python3 -m module2_feature_extraction.examples.run_feature_extraction
```

### Run the test suite
```bash
cd xaf_firewall
python3 -m pytest module2_feature_extraction/tests -v
```

**Expected output:** `41 passed` with no failures or errors.

---

## 6. Verifying Correctness

- **Flow continuity:** `test_extract_accumulates_flow_state_across_multiple_packets`
  and `test_extract_reply_packet_maps_to_same_flow_id` confirm that packets
  belonging to one conversation share a `flow_id` and that counters
  (`total_packets_in_flow`, `total_bytes`) increase correctly.
- **Rates/durations:** `test_flow_builder.py` verifies `packet_rate`,
  `byte_rate`, and `flow_duration` against hand-computed expected values.
- **Direction detection:** `test_determine_direction_*` tests cover
  OUTBOUND, INBOUND, INTERNAL, and malformed-input UNKNOWN cases.
- **Module 1 compatibility:** `test_feature_extractor.py` constructs
  `PacketData` objects using Module 1's *actual, unmodified* `models.py`
  and `ProtocolType` enum — proving the two modules interoperate as-is.
- **Graceful degradation:** `test_extract_gracefully_handles_missing_extra_fields`
  confirms Module 2 does not crash or misbehave when Module 1's `extra`
  dict is empty (today's default behavior).

## 7. Common Errors & Fixes

| Error | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: No module named 'models'` | Running a Module 2 file without importing through the `module1_packet_capture` package (bypassing its `__init__.py` path fix) | Always `import module1_packet_capture` (or import something from it) before/instead of importing `capture.py` directly by path |
| `PermissionError` during `live_capture_demo()` | Packet sniffing needs elevated privileges | Run with `sudo` (Linux/macOS) or as Administrator (Windows) |
| `ModuleNotFoundError: No module named 'scapy'` | Scapy not installed | `pip install scapy --break-system-packages` |
| Tests can't find `module2_feature_extraction` | Running pytest from the wrong directory | `cd` into `xaf_firewall/` before running `pytest` |
| `fv.ttl` / `fv.tcp_flags` always `None` | Module 1 doesn't currently populate `PacketData.extra` | Expected with unmodified Module 1; see optional enhancement in Section 3 |

---

## 8. Module 2 Completion Checklist

- [x] Complete folder structure created
- [x] `FeatureVector` model implemented (all Basic + Advanced + Statistics fields)
- [x] Feature extraction engine (`FeatureExtractionEngine`) implemented
- [x] Flow builder (`FlowBuilder` / `FlowRecord`) implemented
- [x] Session manager (`SessionManager`) implemented — creation, expiry, eviction, aggregate stats
- [x] Utility functions (`utils.py`) implemented and unit-tested
- [x] Configuration file (`config.py`) implemented
- [x] Logger (`logger.py`) implemented
- [x] Unit tests written — 41 tests, all passing
- [x] Example runner (`examples/run_feature_extraction.py`) implemented and verified
- [x] Zero modifications to Module 1's `capture.py`, `models.py`, `utils.py` (checksum-verified)
- [x] All required integration changes documented separately (Section 3), not silently applied
- [x] No IDS, AI detection, firewall blocking, or dashboard logic included
- [x] Clean architecture maintained: entities (`models.py`) → helpers (`utils.py`) →
      single-responsibility services (`flow_builder.py`, `session_manager.py`) →
      orchestration (`feature_extractor.py`)

**Module 2 is complete and ready for integration with Module 3 (AI Detection Engine).**
Module 3 should depend only on `FeatureExtractionEngine.extract()` /
`extract_batch()` and the `FeatureVector` model — not on any internal
class in this module.
