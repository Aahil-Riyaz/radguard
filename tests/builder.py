"""Byte-exact DICOM writer for tests.

It writes exactly what it is told, including things the standard forbids, so
tests can build both conforming files and hostile ones. Every payload is
inert: correct magic bytes and headers, no working code.
"""

from __future__ import annotations

import struct
import zlib

IMPLICIT_LE = "1.2.840.10008.1.2"
EXPLICIT_LE = "1.2.840.10008.1.2.1"
DEFLATED_LE = "1.2.840.10008.1.2.1.99"
EXPLICIT_BE = "1.2.840.10008.1.2.2"
JPEG_BASELINE = "1.2.840.10008.1.2.4.50"
CT_IMAGE_STORAGE = "1.2.840.10008.5.1.4.1.1.2"

UNDEF = 0xFFFFFFFF
PIXEL_DATA = 0x7FE00010
_LONG = {"OB", "OD", "OF", "OL", "OV", "OW", "SQ", "UC", "UN", "UR", "UT", "SV", "UV"}


def _e(little: bool) -> str:
    return "<" if little else ">"


def tag(t: int, little: bool = True) -> bytes:
    return struct.pack(_e(little) + "HH", t >> 16, t & 0xFFFF)


def text(value: str, vr: str = "LO") -> bytes:
    data = value.encode("ascii")
    if len(data) % 2:
        data += b"\x00" if vr == "UI" else b" "
    return data


def el(t: int, vr: str, value: bytes | str = b"", *, implicit=False, little=True, length=None) -> bytes:
    if isinstance(value, str):
        value = text(value, vr)
    n = len(value) if length is None else length
    e = _e(little)
    if implicit:
        return tag(t, little) + struct.pack(e + "I", n) + value
    if vr in _LONG:
        return tag(t, little) + vr.encode() + b"\x00\x00" + struct.pack(e + "I", n) + value
    return tag(t, little) + vr.encode() + struct.pack(e + "H", n) + value


def us(t: int, *vals: int, implicit=False, little=True) -> bytes:
    return el(t, "US", struct.pack(_e(little) + "H" * len(vals), *vals), implicit=implicit, little=little)


def item(content: bytes = b"", *, undefined=False, little=True) -> bytes:
    e = _e(little)
    if undefined:
        return struct.pack(e + "HHI", 0xFFFE, 0xE000, UNDEF) + content + struct.pack(e + "HHI", 0xFFFE, 0xE00D, 0)
    return struct.pack(e + "HHI", 0xFFFE, 0xE000, len(content)) + content


def seq_delim(little=True) -> bytes:
    return struct.pack(_e(little) + "HHI", 0xFFFE, 0xE0DD, 0)


def seq(t: int, *items: bytes, undefined=False, implicit=False, little=True, vr="SQ") -> bytes:
    body = b"".join(items)
    if undefined:
        return el(t, vr, body + seq_delim(little), implicit=implicit, little=little, length=UNDEF)
    return el(t, vr, body, implicit=implicit, little=little)


def encapsulated(*fragments: bytes, bot: bytes = b"") -> bytes:
    body = item(bot) + b"".join(item(f) for f in fragments) + seq_delim()
    return el(PIXEL_DATA, "OB", body, length=UNDEF)


def meta(ts: str = EXPLICIT_LE, *, group_length=True, group_length_value=None, extra=b"") -> bytes:
    body = (
        el(0x00020001, "OB", b"\x00\x01")
        + el(0x00020002, "UI", CT_IMAGE_STORAGE)
        + el(0x00020003, "UI", "1.2.826.0.1.3680043.10.1")
        + el(0x00020010, "UI", ts)
        + extra
    )
    if group_length:
        value = len(body) if group_length_value is None else group_length_value
        body = el(0x00020000, "UL", struct.pack("<I", value)) + body
    return body


def part10(dataset: bytes = b"", *, ts: str = EXPLICIT_LE, preamble: bytes = b"", **meta_kw) -> bytes:
    return preamble.ljust(128, b"\x00") + b"DICM" + meta(ts, **meta_kw) + dataset


def image(rows: int, cols: int, pixels: bytes | None = None, *, bits=8, frames=None,
          implicit=False, little=True, extra=b"", pixel_element=None) -> bytes:
    """A minimal monochrome CT image dataset, tags in ascending order."""
    kw = {"implicit": implicit, "little": little}
    if pixels is None:
        pixels = bytes(rows * cols * bits // 8)
    out = el(0x00080016, "UI", CT_IMAGE_STORAGE, **kw) + el(0x00080060, "CS", "CT", **kw)
    out += us(0x00280002, 1, **kw) + el(0x00280004, "CS", "MONOCHROME2", **kw)
    if frames is not None:
        out += el(0x00280008, "IS", str(frames), **kw)
    out += us(0x00280010, rows, **kw) + us(0x00280011, cols, **kw)
    out += us(0x00280100, bits, **kw) + us(0x00280101, bits, **kw)
    out += us(0x00280102, bits - 1, **kw) + us(0x00280103, 0, **kw)
    out += extra
    out += pixel_element if pixel_element is not None else el(PIXEL_DATA, "OW" if bits > 8 else "OB", pixels, **kw)
    return out


def deflate(data: bytes) -> bytes:
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def fake_pe(size: int = 128) -> bytes:
    """An inert PE skeleton: MZ stub whose e_lfanew points at a PE signature. No code."""
    data = bytearray(size)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x40)
    data[0x40:0x44] = b"PE\x00\x00"
    return bytes(data)


def fake_elf(size: int = 64) -> bytes:
    """An inert ELF identification header (64-bit, little-endian, version 1). No code."""
    return b"\x7fELF\x02\x01\x01" + bytes(size - 7)
