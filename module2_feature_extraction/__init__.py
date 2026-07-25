"""
module1_packet_capture
-----------------------
Package marker for Module 1 (Packet Capture Engine).

INTEGRATION NOTE (Module 2 build):
This __init__.py is a NEW file added purely so that Module 1's existing,
unmodified files (capture.py, models.py, utils.py) can be imported as a
proper Python package from Module 2 and elsewhere in the XAF project, e.g.:

    from module1_packet_capture.models import PacketData, ProtocolType
    from module1_packet_capture.capture import PacketCaptureEngine

No existing Module 1 source file was edited to create this package. The
original capture.py, models.py, and utils.py are byte-for-byte identical
to the previously delivered Module 1.

INTEGRATION NOTE (flat imports inside capture.py / utils.py):
Module 1's original files use flat, same-directory imports internally
(e.g. capture.py contains `from models import PacketData, ProtocolType`
rather than a relative `.models` import), because Module 1 was originally
delivered as standalone flat files, not a package. Rather than editing
those import lines, this __init__.py adds Module 1's own directory to
sys.path so those original flat imports keep resolving correctly even
though Module 1 is now nested inside a larger project package. This is
a path/packaging accommodation only -- no Module 1 source line was changed.
"""

import os
import sys

_module1_dir = os.path.dirname(os.path.abspath(__file__))
if _module1_dir not in sys.path:
    sys.path.insert(0, _module1_dir)

from module1_packet_capture.models import PacketData, ProtocolType
from module1_packet_capture.capture import PacketCaptureEngine

__all__ = ["PacketData", "ProtocolType", "PacketCaptureEngine"]
