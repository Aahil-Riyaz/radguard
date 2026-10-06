"""Make attacker-controlled text safe to print in a terminal.

File names and anything derived from file contents are attacker-controlled.
Printed raw, they can carry ANSI/VT escape sequences that rewrite the analyst's
terminal (hide lines, fake output, set the window title) or Unicode
bidirectional overrides that make "gpj.exe" display as "exe.jpg" (the "Trojan
Source" class, CVE-2021-42574). Every human-readable line RadGuard prints
goes through `safe`. JSON output is already safe: json.dumps escapes control
characters, and ensure_ascii escapes every non-ASCII code point.

The ranges are built from code points rather than written as literal
characters, so this file stays pure ASCII (tests/test_repo_hygiene.py).
"""

from __future__ import annotations

import re

_UNSAFE_RANGES = (
    (0x00, 0x08),  # C0 controls before tab
    (0x0A, 0x1F),  # C0 controls after tab, including ESC
    (0x7F, 0x9F),  # DEL and C1 controls (CSI 0x9B starts escape sequences on some terminals)
    (0x200B, 0x200F),  # zero-width characters, LRM, RLM
    (0x2028, 0x202E),  # line/paragraph separators, bidi embeddings and overrides
    (0x2060, 0x2064),  # word joiner and invisible operators
    (0x2066, 0x2069),  # bidi isolates
    (0xFEFF, 0xFEFF),  # zero-width no-break space / BOM
)
_UNSAFE = re.compile(
    "[" + "".join(f"{re.escape(chr(lo))}-{re.escape(chr(hi))}" for lo, hi in _UNSAFE_RANGES) + "]"
)


def safe(text: str) -> str:
    return _UNSAFE.sub(lambda m: f"\\u{ord(m.group()):04x}" if ord(m.group()) > 0xFF
                       else f"\\x{ord(m.group()):02x}", text)
