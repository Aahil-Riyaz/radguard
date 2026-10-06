"""File signatures: what does a run of bytes look like it *is*?

Two ways to match:

* `match_prefix` identifies a format whose magic sits at a known offset (the
  preamble). Short magics are fine there because the position is fixed.
* `radguard.carving` searches whole buffers. Anywhere-in-the-file search needs
  far more evidence per hit, or random pixel data produces false positives:
  "#!" turns up every 64 KiB of noise. So each signature has longer
  `scan_magics` plus a structural validator, and only validated hits count.
  With validation the expected false-positive rate in random data is below
  one per terabyte for every signature.
"""

from __future__ import annotations

import math
import re
import struct
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass

from radguard.findings import Severity

Validator = Callable[[object, int], "str | None"]  # (buffer, offset) -> detail, or None to reject


@dataclass(frozen=True)
class Signature:
    kind: str
    label: str
    magics: tuple[bytes, ...]  # matched at a known offset
    severity: Severity
    scan_magics: tuple[bytes, ...]  # searched for anywhere
    validate: Validator | None = None


@dataclass(frozen=True)
class Match:
    offset: int
    signature: Signature
    detail: str = ""


def printable(data: bytes, limit: int = 40) -> str:
    """ASCII-only rendering of attacker-controlled bytes, safe to embed in a finding."""
    text = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in data[:limit])
    return text + ("..." if len(data) > limit else "")


# -- validators ----------------------------------------------------------------

def pe_header(buf, mz_offset: int) -> int | None:
    """Offset of the "PE\\0\\0" header that the MZ stub at `mz_offset` points to, if valid."""
    if mz_offset + 0x40 > len(buf):
        return None
    (e_lfanew,) = struct.unpack_from("<I", buf, mz_offset + 0x3C)
    pe = mz_offset + e_lfanew
    if 0 < e_lfanew and pe + 4 <= len(buf) and buf[pe : pe + 4] == b"PE\x00\x00":
        return pe
    return None


def _pe(buf, pos):
    pe = pe_header(buf, pos)
    return f"PE header at {pe:#x}" if pe is not None else None


_ELF_TYPES = {1: "relocatable object", 2: "executable", 3: "shared object", 4: "core dump"}


def _elf(buf, pos):
    if pos + 18 > len(buf):
        return None
    cls, data, version = buf[pos + 4], buf[pos + 5], buf[pos + 6]
    if cls not in (1, 2) or data not in (1, 2) or version != 1:
        return None
    (e_type,) = struct.unpack_from("<H" if data == 1 else ">H", buf, pos + 16)
    if e_type not in _ELF_TYPES:
        return None
    return f"{32 * cls}-bit {_ELF_TYPES[e_type]}"


_MACHO_CPUS = {7: "x86", 0x01000007: "x86_64", 12: "ARM", 0x0100000C: "ARM64", 18: "PowerPC", 0x01000012: "PowerPC64"}


def _macho(buf, pos):
    if pos + 8 > len(buf):
        return None
    little = buf[pos] in (0xCE, 0xCF)
    (cpu,) = struct.unpack_from("<I" if little else ">I", buf, pos + 4)
    return _MACHO_CPUS.get(cpu)


def _fat_or_class(buf, pos):
    if pos + 8 > len(buf):
        return None
    first, second = struct.unpack_from(">HH", buf, pos + 4)
    if 45 <= second <= 80:  # Java: minor, major version
        return f"Java class file, version {second}.{first}"
    (count,) = struct.unpack_from(">I", buf, pos + 4)
    return f"universal binary with {count} architectures" if 1 <= count <= 32 else None


_INTERPRETER = re.compile(rb"#!(/[\w./-]{2,64})[ \t]*[\w./ -]{0,64}\r?\n")


def _shebang(buf, pos):
    m = _INTERPRETER.match(bytes(buf[pos : pos + 160]))
    return f"interpreter {printable(m.group(1))}" if m else None


_ZIP_METHODS = {0, 8, 9, 12, 14, 93, 95, 98, 99}


def _zip(buf, pos):
    if pos + 30 > len(buf):
        return None
    version, _, method = struct.unpack_from("<HHH", buf, pos + 4)
    name_len, extra_len = struct.unpack_from("<HH", buf, pos + 26)
    if version > 63 or method not in _ZIP_METHODS or not 1 <= name_len <= 1024:
        return None
    return f"first entry {printable(bytes(buf[pos + 30 : pos + 30 + name_len]))}"


def _ole(buf, pos):
    return "" if buf[pos + 28 : pos + 30] == b"\xfe\xff" else None  # byte-order mark


def _pdf(buf, pos):
    version = bytes(buf[pos + 5 : pos + 8])
    return f"PDF {version.decode()}" if re.fullmatch(rb"\d\.\d", version) else None


def _rtf(buf, pos):
    return "" if pos + 6 <= len(buf) and (chr(buf[pos + 5]).isalnum() or buf[pos + 5] == 0x5C) else None


def _upper(*magics: bytes) -> tuple[bytes, ...]:
    return magics + tuple(m.upper() for m in magics)


SIGNATURES: tuple[Signature, ...] = (
    Signature("pe", "Windows PE executable", (b"MZ",), Severity.CRITICAL, (b"MZ",), _pe),
    Signature("elf", "ELF executable", (b"\x7fELF",), Severity.CRITICAL, (b"\x7fELF",), _elf),
    Signature("macho", "Mach-O executable",
              (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"),
              Severity.CRITICAL,
              (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"), _macho),
    Signature("fat-or-class", "Mach-O universal binary or Java class", (b"\xca\xfe\xba\xbe",), Severity.HIGH,
              (b"\xca\xfe\xba\xbe",), _fat_or_class),
    Signature("shebang", "script (#! interpreter line)", (b"#!",), Severity.HIGH, (b"#!/",), _shebang),
    Signature("zip", "ZIP container (JAR/APK/Office/archive)", (b"PK\x03\x04",), Severity.HIGH,
              (b"PK\x03\x04",), _zip),
    Signature("ole", "OLE compound file (MSI/legacy Office)", (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",), Severity.HIGH,
              (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",), _ole),
    Signature("markup", "HTML/XML/SVG markup",
              (b"<html", b"<!doctype", b"<script", b"<svg", b"<?xml", b"<iframe"), Severity.HIGH,
              _upper(b"<script", b"<html", b"<!doctype html", b"<iframe", b"<svg ", b"<svg>", b"<?xml ")),
    Signature("pdf", "PDF document", (b"%PDF",), Severity.MEDIUM, (b"%PDF-",), _pdf),
    Signature("rtf", "RTF document", (b"{\\rtf",), Severity.MEDIUM, (b"{\\rtf",), _rtf),
    Signature("archive", "7z/RAR archive", (b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07"), Severity.MEDIUM,
              (b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07")),
)


def match_prefix(buf, start: int, end: int) -> Match | None:
    """Identify a format whose magic sits exactly at `start` (no confirmation required)."""
    head = bytes(buf[start : min(end, start + 64)])
    for sig in SIGNATURES:
        if sig.kind == "markup":
            if head.lstrip(b" \t\r\n").lower().startswith(sig.magics):
                return Match(start, sig)
        elif head.startswith(sig.magics):
            return Match(start, sig)
    return None


def match_text(match: Match) -> str:
    extra = f" ({match.detail})" if match.detail else ""
    return f"{match.signature.label} at {match.offset:#x}{extra}"


def entropy(data: bytes) -> float:
    n = len(data)
    if not n:
        return 0.0
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def describe(buf, start: int, end: int, sample: int = 4096) -> str:
    data = bytes(buf[start : min(end, start + sample)])
    if not data:
        return "empty"
    share = sum(32 <= b < 127 for b in data) / len(data)
    scope = f" over the first {sample:,} bytes" if end - start > sample else ""
    return (
        f"first bytes {data[:16].hex(' ')}; "
        f"entropy {entropy(data):.2f} bits/byte{scope}; {share:.0%} printable"
    )
