"""Structural integrity: parser anomalies, unexplained bytes and abused padding.

Every byte the parser cannot account for is carved for embedded files. Each
anomaly maps to a rule saying how severe it is and *why it matters*: most of
them are places where two DICOM readers would interpret the same bytes
differently (a parser differential) or where C/C++ decoders historically had
memory-safety bugs.
"""

from __future__ import annotations

from collections.abc import Iterator

from radguard import signatures
from radguard.carving import Exhaustion
from radguard.context import FileContext
from radguard.dicom import coverage
from radguard.dicom.model import PIXEL_DATA, TRAILING_PADDING, Anomaly, Buffer, Element
from radguard.findings import Finding, Severity
from radguard.signatures import Match

C, H, M, L = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW
_DIFFERENTIAL = "different DICOM readers will interpret these bytes differently"

# code: (severity, title, why it matters)
RULES: dict[str, tuple[Severity, str, str]] = {
    "invalid-vr": (H, "Invalid VR",
                   "compliant parsers stop or desynchronise here, so nothing after it is visible to them"),
    "length-overflow": (H, "Declared length exceeds its container",
                        "decoders that trust declared lengths read past the end of their buffer, the trigger "
                        "for a long line of DICOM viewer memory-safety bugs"),
    "truncated-header": (L, "File ends mid-element", "usually an interrupted transfer"),
    "odd-length": (L, "Odd value length", "PS3.5 requires even lengths; " + _DIFFERENTIAL),
    "duplicate-tag": (M, "Duplicate attribute",
                      "readers keep either the first or the last copy, so different software sees different values"),
    "tag-order": (M, "Attributes out of order",
                  "readers that stop early or search by tag will miss attributes that others see"),
    "meta-group-length-mismatch": (H, "File Meta group length is wrong",
                                   "readers that trust the length and readers that scan by group disagree on "
                                   "where the dataset, and its transfer syntax, begins"),
    "missing-meta-group-length": (L, "File Meta group length missing",
                                  "required by PS3.10; some readers mis-locate the dataset without it"),
    "group-length-mismatch": (M, "Group length is wrong",
                              "readers that use group lengths to skip groups will skip a different range of bytes"),
    "transfer-syntax-mismatch": (H, "Transfer syntax does not match the encoding",
                                 "lenient readers silently switch encodings and strict ones fail, so the same file "
                                 "decodes differently depending on the software"),
    "missing-transfer-syntax": (M, "No transfer syntax", "readers must guess how the dataset is encoded"),
    "unknown-transfer-syntax": (L, "Non-standard transfer syntax",
                                "most software cannot decode it; may indicate a private or crafted encoding"),
    "reserved-nonzero": (L, "Reserved header bytes are not zero", "a covert channel that strict readers reject"),
    "vr-mismatch": (M, "Attribute encoded with the wrong VR",
                    "dictionary-driven and header-driven readers decode different values from the same bytes"),
    "vr-length-mismatch": (M, "Value length does not fit its VR",
                           "readers disagree on how many values there are and may read partial values"),
    "stray-delimiter": (H, "Delimiter outside its structure", _DIFFERENTIAL),
    "bad-sequence-item": (H, "Corrupt sequence", _DIFFERENTIAL),
    "missing-item-delimiter": (M, "Unterminated item", "readers disagree about where the item ends"),
    "missing-sequence-delimiter": (M, "Unterminated sequence", "readers disagree about where the sequence ends"),
    "unexpected-delimiter": (M, "Sequence delimiter inside a defined-length sequence",
                             "readers that honour the delimiter end the sequence early"),
    "delimiter-length": (L, "Delimiter with non-zero length", "readers that honour the length skip extra bytes"),
    "undefined-length-invalid": (H, "Undefined length on a non-sequence attribute",
                                 "readers have no way to find where the value ends"),
    "max-depth": (H, "Sequences nested too deeply",
                  "recursive parsers can be driven to stack exhaustion (denial of service)"),
    "element-limit": (H, "Too many elements",
                      "element floods exhaust memory in parsers that build a full object tree"),
    "deflate-bomb": (H, "Decompression bomb", "the deflated dataset expands far beyond any real image"),
    "deflate-truncated": (M, "Truncated deflate stream", "readers recover different amounts of the dataset"),
    "deflate-error": (H, "Corrupt deflate stream", "the dataset cannot be decoded"),
    "unterminated-pixel-data": (M, "Encapsulated pixel data not terminated",
                                "decoders disagree about where the last frame ends"),
    "bad-fragment-item": (H, "Corrupt pixel data fragment", "frame decoders resynchronise differently"),
    "undefined-fragment-length": (H, "Pixel data fragment with undefined length",
                                  "not allowed; decoders cannot find the fragment's end"),
    "bad-offset-table": (M, "Basic Offset Table points outside the fragments",
                         "decoders that seek frames through the table read the wrong bytes"),
    "no-part10-header": (L, "No DICOM Part 10 header",
                         "strict readers reject the file but lenient ones (pydicom's force mode, many toolkits) "
                         "read it, so tools that only look for the DICM marker skip it entirely"),
    "suppressed": (M, "Anomaly flood",
                   "a file that trips the same rule thousands of times is built to flood analysis; "
                   "only the first occurrences are reported"),
}


def check(ctx: FileContext) -> Iterator[Finding]:
    parsed = ctx.parsed
    domains = [("file", ctx.buf, parsed.regions, parsed.size)]
    if parsed.inflated is not None:
        domains.append(("inflated", parsed.inflated, parsed.inflated_regions, len(parsed.inflated)))

    # An anomaly that made the parser give up explains the gap that starts where it stopped.
    causes = {(a.domain, a.offset): a for a in parsed.anomalies if a.code != "suppressed"}
    explained: set[int] = set()
    for domain, buf, regions, size in domains:
        index = ctx.matches(domain)
        for start, end in coverage.gaps(regions, size):
            cause = causes.get((domain, start))
            if cause is not None:
                explained.add(id(cause))
            yield _gap_finding(ctx.path, buf, start, end, domain, cause, index.within(start, end))
        for gap in index.exhausted:
            yield _incomplete(ctx.path, domain, gap)

    for a in parsed.anomalies:
        if a.code == "duplicate-tag" and a.tag == PIXEL_DATA:
            continue  # reported with full context by the pixels check
        if id(a) not in explained:
            severity, title, why = RULES[a.code]
            yield Finding(f"structure.{a.code}", severity, title,
                          f"{_where(a.domain)}{a.message}; {why}", ctx.path, a.offset)

    for el in parsed.elements:
        if el.tag == TRAILING_PADDING and el.depth == 0:
            hits = ctx.matches(el.domain).within(el.value_offset, el.end)
            yield from _padding(ctx.path, parsed.buffer(el.domain, ctx.buf), el, hits)


def _gap_finding(path: str, buf: Buffer, start: int, end: int, domain: str, cause: Anomaly | None,
                 hits: list[Match]) -> Finding:
    n = end - start
    if hits:
        top = max(hits, key=lambda m: m.signature.severity)
        check_id = "structure.hidden-payload"
        severity = max(Severity.HIGH, top.signature.severity)
        title = f"{top.signature.label} hidden in {n:,} bytes outside the DICOM structure"
    else:
        check_id = "structure.unexplained-bytes"
        severity = Severity.LOW if n < 16 else Severity.MEDIUM if n < 1024 else Severity.HIGH
        title = f"{n:,} bytes not accounted for by the DICOM structure"
    parts = []
    if cause is not None:
        parts.append(f"parsing stopped because {cause.message}")
    if hits:
        parts.append("contains " + ", ".join(signatures.match_text(m) for m in hits[:5]))  # pragma: no mutate (display)
    parts.append(signatures.describe(buf, start, end))
    detail = f"{_where(domain)}bytes {start:#x}-{end:#x}: " + "; ".join(parts)
    return Finding(check_id, severity, title, detail, path, start)


def _padding(path: str, buf: Buffer, el: Element, hits: list[Match]) -> Iterator[Finding]:
    # Data Set Trailing Padding has no meaning (PS3.10 7.2), so readers skip it unread.
    data = bytes(buf[el.value_offset : el.end])
    nonzero = len(data) - data.count(0)
    if not nonzero:
        return
    severity = max(Severity.HIGH, *(m.signature.severity for m in hits)) if hits else Severity.MEDIUM
    detail = (f"{_where(el.domain)}(FFFC,FFFC) Data Set Trailing Padding holds {nonzero:,} non-zero bytes; "
              "readers skip padding without looking at it")
    if hits:
        detail += "; contains " + ", ".join(signatures.match_text(m) for m in hits[:5])  # pragma: no mutate (display)
    detail += "; " + signatures.describe(buf, el.value_offset, el.end)
    yield Finding("structure.nonzero-padding", severity, "Data hidden in trailing padding",
                  detail, path, el.value_offset)


def _incomplete(path: str, domain: str, gap: Exhaustion) -> Finding:
    # Never let a budget turn into a blind spot: say exactly what was not examined.
    adversarial = gap.reason != "size"
    return Finding(
        "structure.analysis-incomplete", Severity.HIGH if adversarial else Severity.LOW,
        "File built to exhaust analysis" if adversarial else "File larger than the inspection window",
        f"{_where(domain)}{gap.detail} (from offset {gap.offset:#x})", path, gap.offset,
    )


def _where(domain: str) -> str:
    return "[offsets within the inflated dataset] " if domain == "inflated" else ""
