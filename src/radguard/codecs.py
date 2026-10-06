"""Where does a compressed frame really end?

Decoders stop at the codestream's end marker, so bytes after it are never
displayed, which makes them a hiding place exactly like slack after native pixels.
These walkers find the true end of a frame by following the marker structure
of each codec, not by searching for the first plausible end marker: a JPEG can
carry a thumbnail with its own EOI inside an APP1 segment, and JPEG 2000 header
segments can contain FF D9 by coincidence.

All walkers are bounded: scans inside entropy-coded data run in C (re), marker
segments are capped, and every loop iteration advances by at least two bytes.
Each returns (end offset or None, problem or None).
"""

from __future__ import annotations

import re
import struct

MAX_SEGMENTS = 100_000  # marker segments walked per frame

# After SOS, entropy-coded data runs until a real marker. In JPEG (ITU T.81 B.1.1.5)
# FF 00 is a stuffed byte and FF D0-D7 are restart markers inside the scan; FF FF is fill.
_JPEG_SCAN_END = re.compile(rb"\xff[^\x00\xd0-\xd7\xff]")
# In JPEG-LS (ITU T.87 A.1) a marker is FF followed by a byte with its high bit set.
_JPEG_LS_SCAN_END = re.compile(rb"\xff[\x80-\xfe]")
_NOT_FILL = re.compile(rb"[^\xff]")
_STANDALONE = frozenset({0x01, *range(0xD0, 0xD8)})  # TEM, RST0-RST7: no length field


def jpeg_end(data: bytes, *, ls: bool = False) -> tuple[int | None, str | None]:
    """End of a JPEG (T.81) or JPEG-LS (T.87) codestream: the byte after EOI."""
    if not data.startswith(b"\xff\xd8"):
        return None, "does not start with SOI (FF D8)"
    scan_end = _JPEG_LS_SCAN_END if ls else _JPEG_SCAN_END
    n, pos = len(data), 2
    for _ in range(MAX_SEGMENTS):
        if pos >= n:
            break
        if data[pos] != 0xFF:
            return None, f"expected a marker at frame offset {pos:#x}"
        fill_end = _NOT_FILL.search(data, pos)  # any number of FF fill bytes may precede a marker
        if fill_end is None:
            break
        code, pos = data[fill_end.start()], fill_end.start() + 1
        if code == 0xD9:
            return pos, None
        if code in _STANDALONE:
            continue
        if code == 0xD8:
            return None, f"second SOI inside the codestream at frame offset {pos - 2:#x}"
        if pos + 2 > n:
            break
        (length,) = struct.unpack_from(">H", data, pos)
        if length < 2:
            return None, f"marker FF {code:02X} has invalid length {length}"
        pos += length
        if pos > n:
            return None, f"marker FF {code:02X} segment runs past the end of the frame"
        if code == 0xDA:  # SOS: skip the entropy-coded data
            marker = scan_end.search(data, pos)
            if marker is None:
                break
            pos = marker.start()
    else:
        return None, f"more than {MAX_SEGMENTS:,} marker segments"
    return None, "no EOI (FF D9) before the end of the frame"


def j2k_end(data: bytes) -> tuple[int | None, str | None]:
    """End of a JPEG 2000 / HTJ2K codestream (T.800 Annex A): the byte after EOC."""
    if not data.startswith(b"\xff\x4f\xff\x51"):
        return None, "does not start with SOC + SIZ (FF 4F FF 51)"
    n, pos = len(data), 2
    pos, problem = _skip_segments(data, pos, stop=0xFF90, where="main header")  # up to the first SOT
    if problem:
        return None, problem
    for _ in range(MAX_SEGMENTS):
        if pos + 12 > n or data[pos : pos + 2] != b"\xff\x90":
            break
        (psot,) = struct.unpack_from(">I", data, pos + 6)  # SOT: Lsot, Isot, Psot, TPsot, TNsot
        if psot == 0:
            # Only the last tile-part may omit its length; its data runs to EOC. Packet
            # data cannot contain FF followed by a byte above 0x8F, so after SOD the
            # first FF D9 is EOC.
            sod, problem = _skip_segments(data, pos + 12, stop=0xFF93, where="tile-part header")
            if problem:
                return None, problem
            eoc = data.find(b"\xff\xd9", sod)
            return (eoc + 2, None) if eoc != -1 else (None, "no EOC (FF D9) after the last tile-part")
        if psot < 14:
            return None, f"tile-part at frame offset {pos:#x} has invalid length {psot}"
        pos += psot
    else:
        return None, f"more than {MAX_SEGMENTS:,} tile-parts"
    if data[pos : pos + 2] == b"\xff\xd9":
        return pos + 2, None
    return None, f"expected EOC (FF D9) at frame offset {pos:#x}"


def _skip_segments(data: bytes, pos: int, *, stop: int, where: str) -> tuple[int, str | None]:
    for _ in range(MAX_SEGMENTS):
        if pos + 4 > len(data):
            return pos, f"{where} runs past the end of the frame"
        marker, length = struct.unpack_from(">HH", data, pos)
        if marker == stop:
            return pos, None
        if marker >> 8 != 0xFF or length < 2:
            return pos, f"invalid {where} marker {marker:04X} at frame offset {pos:#x}"
        pos += 2 + length
    return pos, f"more than {MAX_SEGMENTS:,} {where} segments"


def rle_problem(data: bytes) -> str | None:
    """Validate the 64-byte RLE Lossless header (PS3.5 Annex G.5)."""
    if len(data) < 64:
        return "frame is shorter than the 64-byte RLE header"
    count, *offsets = struct.unpack_from("<16I", data)
    if not 1 <= count <= 15:
        return f"segment count {count} is outside 1-15"
    used = offsets[:count]
    if used[0] != 64 or any(b <= a for a, b in zip(used, used[1:])) or used[-1] >= len(data):
        return "segment offsets are not increasing within the frame"
    if any(offsets[count:]):
        return "unused segment offsets are not zero"
    return None
