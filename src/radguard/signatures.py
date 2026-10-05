"""Shared file-signature engine: what does a run of bytes look like it *is*?

Used wherever bytes have no business containing another file format: the
preamble, bytes the DICOM grammar cannot account for, pixel-data slack and
trailing padding.
"""

from __future__ import annotations

import math
import struct
from collections import Counter
from dataclasses import dataclass

from radguard.findings import Severity


@dataclass(frozen=True)
class Signature:
    kind: str
    label: str
    magics: tuple[bytes, ...]
    severity: Severity

    @property
    def scan_magics(self) -> tuple[bytes, ...]:
        # Searching anywhere in a region needs stricter magics than matching at
        # a known offset: "#!" occurs by chance every few KiB of random data.
        if self.kind == "shebang":
            return (b"#!/",)
        if self.kind == "markup":
            return self.magics + tuple(m.upper() for m in self.magics)
        return self.magics


SIGNATURES: tuple[Signature, ...] = (
    Signature("pe", "Windows PE executable", (b"MZ",), Severity.CRITICAL),
    Signature("elf", "ELF executable", (b"\x7fELF",), Severity.CRITICAL),
    Signature("macho", "Mach-O executable",
              (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"),
              Severity.CRITICAL),
    Signature("fat-or-class", "Mach-O universal binary or Java class", (b"\xca\xfe\xba\xbe",), Severity.HIGH),
    Signature("shebang", "script (#! interpreter line)", (b"#!",), Severity.HIGH),
    Signature("zip", "ZIP container (JAR/APK/Office/archive)", (b"PK\x03\x04",), Severity.HIGH),
    Signature("ole", "OLE compound file (MSI/legacy Office)", (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",), Severity.HIGH),
    Signature("markup", "HTML/XML/SVG markup",
              (b"<html", b"<!doctype", b"<script", b"<svg", b"<?xml", b"<iframe"), Severity.HIGH),
    Signature("pdf", "PDF document", (b"%PDF",), Severity.MEDIUM),
    Signature("rtf", "RTF document", (b"{\\rtf",), Severity.MEDIUM),
    Signature("archive", "7z/RAR archive", (b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07"), Severity.MEDIUM),
)

SCAN_LIMIT = 64 << 20  # bytes searched per region
MAX_HITS = 16  # confirmed matches kept per magic
MAX_CANDIDATES = 4096  # raw magic hits examined per magic (bounds work on hostile input)


@dataclass(frozen=True)
class Match:
    offset: int
    signature: Signature
    detail: str = ""


def pe_header(buf, mz_offset: int) -> int | None:
    """Offset of the "PE\\0\\0" header that the MZ stub at `mz_offset` points to, if valid."""
    if mz_offset + 0x40 > len(buf):
        return None
    (e_lfanew,) = struct.unpack_from("<I", buf, mz_offset + 0x3C)
    pe = mz_offset + e_lfanew
    if 0 < e_lfanew and pe + 4 <= len(buf) and buf[pe : pe + 4] == b"PE\x00\x00":
        return pe
    return None


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


def scan(buf, start: int, end: int, *, limit: int = SCAN_LIMIT) -> list[Match]:
    """Find embedded files anywhere in buf[start:end], keeping only confirmed matches."""
    end = min(end, len(buf), start + limit)
    hits: list[Match] = []
    for sig in SIGNATURES:
        for magic in sig.scan_magics:
            found = candidates = 0
            pos = buf.find(magic, start, end)
            while pos != -1 and found < MAX_HITS and candidates < MAX_CANDIDATES:
                candidates += 1
                match = _confirm(buf, pos, sig)
                if match:
                    hits.append(match)
                    found += 1
                pos = buf.find(magic, pos + 1, end)
    hits.sort(key=lambda m: m.offset)
    return hits


def _confirm(buf, pos: int, sig: Signature) -> Match | None:
    if sig.kind == "pe":
        # A bare "MZ" appears by chance every 64 KiB of random data; require
        # the stub's e_lfanew pointer to land on a real PE header.
        pe = pe_header(buf, pos)
        return Match(pos, sig, f"PE header at {pe:#x}") if pe is not None else None
    if sig.kind == "elf":
        # EI_CLASS and EI_DATA must be 1 or 2, EI_VERSION must be 1.
        if pos + 7 <= len(buf) and buf[pos + 4] in (1, 2) and buf[pos + 5] in (1, 2) and buf[pos + 6] == 1:
            return Match(pos, sig)
        return None
    return Match(pos, sig)


def entropy(data: bytes) -> float:
    n = len(data)
    if not n:
        return 0.0
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def describe(buf, start: int, end: int, sample: int = 4096) -> str:
    data = bytes(buf[start : min(end, start + sample)])
    if not data:
        return "empty"
    printable = sum(32 <= b < 127 for b in data) / len(data)
    scope = f" over the first {sample:,} bytes" if end - start > sample else ""
    return (
        f"first bytes {data[:16].hex(' ')}; "
        f"entropy {entropy(data):.2f} bits/byte{scope}; {printable:.0%} printable"
    )
