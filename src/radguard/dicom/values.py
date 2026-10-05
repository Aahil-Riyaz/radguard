"""Decode element values on demand. The parser itself never copies values."""

from __future__ import annotations

import struct

from radguard.dicom.model import Element

_NUMERIC = {"US": "H", "SS": "h", "UL": "I", "SL": "i", "FL": "f", "FD": "d", "SV": "q", "UV": "Q"}
_STRINGS = frozenset({
    "AE", "AS", "CS", "DA", "DS", "DT", "IS", "LO", "LT", "PN", "SH", "ST", "TM", "UC", "UI", "UR", "UT",
})


def raw(buf, el: Element, limit: int | None = None) -> bytes:
    end = el.end if limit is None else min(el.end, el.value_offset + limit)
    return bytes(buf[el.value_offset : end])


def number(buf, el: Element) -> int | None:
    """First value of an integer attribute (US/SS/UL/SL, or IS/DS text), else None."""
    fmt = _NUMERIC.get(el.vr)
    if fmt in ("H", "h", "I", "i"):
        size = struct.calcsize(fmt)
        data = raw(buf, el, size)
        if len(data) == size:
            return struct.unpack(("<" if el.little else ">") + fmt, data)[0]
        return None
    if el.vr in ("IS", "DS"):
        first = raw(buf, el, 64).split(b"\\")[0].strip(b" \x00")
        try:
            return int(float(first))
        except (ValueError, OverflowError):
            return None
    return None


def text(buf, el: Element, width: int = 40) -> str:
    """Short, ASCII-only rendering of a value for display."""
    n = el.end - el.value_offset
    fmt = _NUMERIC.get(el.vr)
    if fmt:
        size = struct.calcsize(fmt)
        count = min(n // size, 6)
        data = raw(buf, el, count * size)
        vals = struct.unpack(f"{'<' if el.little else '>'}{count}{fmt}", data) if count else ()
        out = "\\".join(f"{v:g}" if isinstance(v, float) else str(v) for v in vals)
        if n // size > count:
            out += "\\..."
    elif el.vr in _STRINGS:
        decoded = raw(buf, el, width * 2).rstrip(b" \x00").decode("ascii", "replace")
        out = '"' + "".join(ch if " " <= ch <= "~" else "." for ch in decoded) + '"'
    else:
        out = f"<{n:,} bytes>"
    return out if len(out) <= width else out[: width - 3] + "..."
