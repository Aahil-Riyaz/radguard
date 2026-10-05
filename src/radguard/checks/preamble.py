"""Detect executable or script content hidden in the DICOM Part 10 preamble.

A Part 10 file starts with a 128-byte preamble followed by the magic "DICM".
The standard leaves the preamble free for application use, so one file can be
a valid CT slice *and* a valid Windows PE or Linux ELF executable at the same
time (CVE-2019-11687, ELFDICOM). Viewers open it normally, and because it is
"just a scan" full of patient data it often escapes malware inspection.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator

from radguard import signatures
from radguard.context import PREAMBLE_LEN, FileContext
from radguard.findings import Finding, Severity

CVE_2019_11687 = "https://nvd.nist.gov/vuln/detail/CVE-2019-11687"
ELFDICOM = (
    "https://www.praetorian.com/blog/"
    "elfdicom-poc-malware-polyglot-exploiting-linux-based-medical-devices/"
)
PS3_10_PREAMBLE = "https://dicom.nema.org/medical/dicom/current/output/chtml/part10/chapter_7.html"

# PS3.10 section 7.1 explicitly allows a TIFF header (dual TIFF/DICOM files).
BENIGN_PREFIXES = (b"II*\x00", b"MM\x00*")

# Executables get a "-polyglot" suffix: the file is runnable *and* a valid image.
_CHECK_IDS = {"elf": "elf-polyglot", "macho": "macho-polyglot"}


def check(ctx: FileContext) -> Iterator[Finding]:
    pre = ctx.preamble
    if not any(pre) or pre.startswith(BENIGN_PREFIXES):
        return

    match = signatures.match_prefix(ctx.buf, 0, PREAMBLE_LEN)
    detail = signatures.describe(ctx.buf, 0, PREAMBLE_LEN)
    if match is None:
        yield Finding(
            "preamble.nonstandard", Severity.LOW, "Unrecognised non-zero preamble",
            detail, ctx.path, 0, (PS3_10_PREAMBLE,),
        )
        return

    sig = match.signature
    if sig.kind == "pe":
        yield _pe_finding(ctx)
        return

    polyglot = " (polyglot)" if sig.severity is Severity.CRITICAL else ""
    yield Finding(
        f"preamble.{_CHECK_IDS.get(sig.kind, sig.kind)}", sig.severity,
        f"{sig.label} header in preamble{polyglot}",
        detail, ctx.path, 0, (ELFDICOM if sig.kind == "elf" else CVE_2019_11687,),
    )


def _pe_finding(ctx: FileContext) -> Finding:
    # e_lfanew (offset 0x3C, still inside the preamble) points to "PE\0\0". In
    # a real PE/DICOM polyglot it lands inside a DICOM data element further in.
    pe = signatures.pe_header(ctx.buf, 0)
    if pe is not None:
        return Finding(
            "preamble.pe-polyglot", Severity.CRITICAL,
            "Windows PE executable embedded via preamble (PE/DICOM polyglot)",
            f"MZ header with PE signature at offset {pe:#x}; the file is "
            "laid out as a Windows executable as well as a DICOM image",
            ctx.path, pe, (CVE_2019_11687,),
        )
    (e_lfanew,) = struct.unpack_from("<I", ctx.buf, 0x3C)
    return Finding(
        "preamble.mz-header", Severity.HIGH,
        "DOS/PE 'MZ' header in preamble",
        f"e_lfanew={e_lfanew:#x} does not point at a PE signature; likely a "
        "truncated or staged payload. " + signatures.describe(ctx.buf, 0, PREAMBLE_LEN),
        ctx.path, 0, (CVE_2019_11687,),
    )
