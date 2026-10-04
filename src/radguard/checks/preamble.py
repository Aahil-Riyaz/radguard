"""Detect executable or script content hidden in the DICOM Part 10 preamble.

A Part 10 file starts with a 128-byte preamble followed by the magic "DICM".
The standard leaves the preamble free for application use, so one file can be
a valid CT slice *and* a valid Windows PE or Linux ELF executable at the same
time (CVE-2019-11687, ELFDICOM). Viewers open it normally, and because it is
"just a scan" full of patient data it often escapes malware inspection.
"""

from __future__ import annotations

import math
import struct
from collections import Counter
from collections.abc import Iterator

from radguard.context import FileContext
from radguard.findings import Finding, Severity

CVE_2019_11687 = "https://nvd.nist.gov/vuln/detail/CVE-2019-11687"
ELFDICOM = (
    "https://www.praetorian.com/blog/"
    "elfdicom-poc-malware-polyglot-exploiting-linux-based-medical-devices/"
)
PS3_10_PREAMBLE = "https://dicom.nema.org/medical/dicom/current/output/chtml/part10/chapter_7.html"

# PS3.10 section 7.1 explicitly allows a TIFF header (dual TIFF/DICOM files).
BENIGN_PREFIXES = (b"II*\x00", b"MM\x00*")

# (magic prefixes, check id, severity, title)
BINARY_SIGNATURES: tuple[tuple[tuple[bytes, ...], str, Severity, str], ...] = (
    ((b"\x7fELF",), "preamble.elf-polyglot", Severity.CRITICAL,
     "ELF executable header in preamble (ELF/DICOM polyglot)"),
    ((b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"),
     "preamble.macho-polyglot", Severity.CRITICAL,
     "Mach-O executable header in preamble"),
    ((b"\xca\xfe\xba\xbe",), "preamble.fat-or-class", Severity.HIGH,
     "Mach-O universal binary or Java class header in preamble"),
    ((b"#!",), "preamble.shebang", Severity.HIGH,
     "Script interpreter line (#!) in preamble"),
    ((b"PK\x03\x04",), "preamble.zip", Severity.HIGH,
     "ZIP container header in preamble (JAR/APK/Office/archive)"),
    ((b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",), "preamble.ole", Severity.HIGH,
     "OLE compound file header in preamble (MSI/legacy Office)"),
    ((b"%PDF",), "preamble.pdf", Severity.MEDIUM,
     "PDF header in preamble"),
    ((b"{\\rtf",), "preamble.rtf", Severity.MEDIUM,
     "RTF header in preamble"),
    ((b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07"), "preamble.archive", Severity.MEDIUM,
     "Archive header in preamble"),
)

MARKUP_PREFIXES = (b"<html", b"<!doctype", b"<script", b"<svg", b"<?xml", b"<iframe")


def check(ctx: FileContext) -> Iterator[Finding]:
    pre = ctx.preamble
    if not any(pre) or pre.startswith(BENIGN_PREFIXES):
        return

    if pre.startswith(b"MZ"):
        yield _check_pe(ctx)
        return

    for prefixes, check_id, severity, title in BINARY_SIGNATURES:
        if pre.startswith(prefixes):
            refs = (ELFDICOM,) if check_id == "preamble.elf-polyglot" else (CVE_2019_11687,)
            yield Finding(check_id, severity, title, _describe(pre), ctx.path, 0, refs)
            return

    if pre.lstrip(b" \t\r\n").lower().startswith(MARKUP_PREFIXES):
        yield Finding(
            "preamble.markup", Severity.HIGH,
            "HTML/XML/SVG markup in preamble (file may render as a web page)",
            _describe(pre), ctx.path, 0, (CVE_2019_11687,),
        )
        return

    yield Finding(
        "preamble.nonstandard", Severity.LOW,
        "Unrecognised non-zero preamble",
        _describe(pre), ctx.path, 0, (PS3_10_PREAMBLE,),
    )


def _check_pe(ctx: FileContext) -> Finding:
    # e_lfanew (offset 0x3C) points to the "PE\0\0" header. In a real PE/DICOM
    # polyglot it lands inside a DICOM data element further into the file.
    (e_lfanew,) = struct.unpack_from("<I", ctx.preamble, 0x3C)
    if 0 < e_lfanew <= ctx.size - 4:
        ctx.fh.seek(e_lfanew)
        if ctx.fh.read(4) == b"PE\x00\x00":
            return Finding(
                "preamble.pe-polyglot", Severity.CRITICAL,
                "Windows PE executable embedded via preamble (PE/DICOM polyglot)",
                f"MZ header with PE signature at offset {e_lfanew:#x}; the file is "
                "laid out as a Windows executable as well as a DICOM image",
                ctx.path, e_lfanew, (CVE_2019_11687,),
            )
    return Finding(
        "preamble.mz-header", Severity.HIGH,
        "DOS/PE 'MZ' header in preamble",
        f"e_lfanew={e_lfanew:#x} does not point at a PE signature; "
        "likely a truncated or staged payload. " + _describe(ctx.preamble),
        ctx.path, 0, (CVE_2019_11687,),
    )


def _describe(pre: bytes) -> str:
    printable = sum(32 <= b < 127 for b in pre) / len(pre)
    return (
        f"first bytes {pre[:16].hex(' ')}; "
        f"entropy {_entropy(pre):.2f} bits/byte; {printable:.0%} printable"
    )


def _entropy(data: bytes) -> float:
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())
