"""Make attacker-controlled text safe to print in a terminal or to emit in a report.

File names and anything derived from file contents are attacker-controlled.
Printed raw, they can carry ANSI/VT escape sequences that rewrite the analyst's
terminal (hide lines, fake output, set the window title) or Unicode
bidirectional overrides that make "gpj.exe" display as "exe.jpg" (the "Trojan
Source" class, CVE-2021-42574). Every human-readable line RadGuard prints
goes through `safe`.

File names need not even be valid Unicode. A POSIX name is bytes, and Python
decodes bytes that are not UTF-8 to lone surrogate code points (PEP 383);
NTFS stores UTF-16 and allows unpaired surrogates outright. A lone surrogate
cannot be encoded in UTF-8, so printing one raises, and a JSON string holding
one is rejected by strict parsers: one hostile file name could abort the text
report or invalidate a whole machine-readable report. `safe` escapes them, and
`dumps` escapes them in every string of a report.

The ranges are built from code points rather than written as literal
characters, so this file stays pure ASCII (tests/test_repo_hygiene.py).
"""

from __future__ import annotations

import json
import re
import sys

_UNSAFE_RANGES = (
    (0x00, 0x08),  # C0 controls before tab
    (0x0A, 0x1F),  # C0 controls after tab, including ESC
    (0x7F, 0x9F),  # DEL and C1 controls (CSI 0x9B starts escape sequences on some terminals)
    (0x200B, 0x200F),  # zero-width characters, LRM, RLM
    (0x2028, 0x202E),  # line/paragraph separators, bidi embeddings and overrides
    (0x2060, 0x2064),  # word joiner and invisible operators
    (0x2066, 0x2069),  # bidi isolates
    (0xD800, 0xDFFF),  # surrogates: never valid on their own, and unencodable
    (0xFEFF, 0xFEFF),  # zero-width no-break space / BOM
)
_UNSAFE = re.compile(
    "[" + "".join(f"{re.escape(chr(lo))}-{re.escape(chr(hi))}" for lo, hi in _UNSAFE_RANGES) + "]"
)


def safe(text: str) -> str:
    # No unsafe code point lies at 0xFF or 0x100, so the threshold has slack on both sides.
    return _UNSAFE.sub(lambda m: f"\\u{ord(m.group()):04x}" if ord(m.group()) > 0xFF  # pragma: no mutate (equivalent)
                       else f"\\x{ord(m.group()):02x}", text)


def valid(text: str) -> str:
    """`text` with every surrogate code point written as a \\udcxx escape, so it is valid Unicode."""
    return text.encode("utf-8", "backslashreplace").decode("utf-8")


def _valid_tree(obj: object) -> object:
    if isinstance(obj, str):
        return valid(obj)
    if isinstance(obj, dict):
        return {valid(k) if isinstance(k, str) else k: _valid_tree(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_valid_tree(v) for v in obj]
    return obj


def dumps(report: object) -> str:
    """Serialise a report as pure-ASCII JSON in which every string is valid Unicode."""
    return json.dumps(_valid_tree(report),
                      ensure_ascii=True,  # the same bytes whatever the console or file encoding
                      indent=2) + "\n"  # pragma: no mutate (display)


def harden_streams() -> None:
    """Never let a character the console cannot encode abort the report.

    With output redirected on Windows, Python encodes stdout in the ANSI code
    page with errors="strict", so a perfectly legitimate file name such as a
    Chinese one raised UnicodeEncodeError halfway through the report.
    Characters the stream cannot represent are written as escapes instead.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="backslashreplace")
