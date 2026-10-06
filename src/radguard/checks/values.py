"""Element values: files embedded inside attributes, and documents that are not what they claim.

Day 2's coverage check finds bytes *outside* the structure. A payload can
also sit inside a perfectly well-formed attribute: a private OB blob, a UN
value, an item deep in a sequence. Every value is covered by the shared
carving index; this check attributes each match to the attribute holding it.

Severity depends on what was found. Executables have no business in any
attribute. Documents and markup inside private attributes are routine vendor
practice (XML headers, PDF reports), so they are reported for review only.
"""

from __future__ import annotations

from collections.abc import Iterator

from radguard import signatures
from radguard.context import FileContext
from radguard.dicom import values
from radguard.dicom.model import PIXEL_DATA, Element
from radguard.dicom.paths import Locator
from radguard.findings import Finding, Severity

ENCAPSULATED_DOCUMENT, MIME_TYPE = 0x00420011, 0x00420012

_IN_VALUE = {
    "pe": Severity.CRITICAL, "elf": Severity.CRITICAL, "macho": Severity.CRITICAL,
    "fat-or-class": Severity.HIGH, "shebang": Severity.HIGH,
    "zip": Severity.MEDIUM, "ole": Severity.MEDIUM, "archive": Severity.MEDIUM,
    "pdf": Severity.LOW, "rtf": Severity.LOW, "markup": Severity.LOW,
}

# What an Encapsulated Document's declared MIME type says its first bytes must be.
_EXPECTED = {
    "application/pdf": "pdf",
    "text/xml": "markup",
    "application/xml": "markup",
}


def check(ctx: FileContext) -> Iterator[Finding]:
    parsed = ctx.parsed
    for domain in ("file", "inflated") if parsed.inflated is not None else ("file",):
        buf = parsed.buffer(domain, ctx.buf)
        locator = Locator(parsed, domain)
        for match in ctx.matches(domain).matches:
            el = locator.element_at(match.offset)
            # Pixel Data and Encapsulated Documents have dedicated checks below and in pixels/codestream.
            if el is None or (el.tag == PIXEL_DATA and el.depth == 0) or el.tag == ENCAPSULATED_DOCUMENT:
                continue
            sig = match.signature
            yield Finding(
                "values.embedded-file", _IN_VALUE[sig.kind],
                f"{sig.label} inside an attribute value",
                f"{signatures.match_text(match)}, {match.offset - el.value_offset:,} bytes into "
                f"{locator.path(el)} ({el.vr}, {el.end - el.value_offset:,} bytes)",
                ctx.path, match.offset,
            )
        for el in parsed.elements:
            if el.tag == ENCAPSULATED_DOCUMENT and el.domain == domain and el.fragments is None:
                yield from _document(ctx, buf, parsed.elements, locator, el)


def _document(ctx: FileContext, buf, elements: list[Element], locator: Locator, doc: Element) -> Iterator[Finding]:
    mime_el = next((e for e in elements if e.tag == MIME_TYPE and e.parent == doc.parent
                    and e.domain == doc.domain), None)
    mime = values.raw(buf, mime_el, 128).rstrip(b" \x00").decode("ascii", "replace").lower() if mime_el else None
    hits = ctx.matches(doc.domain).within(doc.value_offset, doc.end)
    actual = signatures.match_prefix(buf, doc.value_offset, doc.end)
    where = locator.path(doc)

    executables = [m for m in hits if m.signature.severity is Severity.CRITICAL]
    if executables:
        yield Finding("values.document-payload", Severity.CRITICAL, "Executable inside an encapsulated document",
                      f"{where} declares {mime or 'no MIME type'} but contains "
                      + ", ".join(signatures.match_text(m) for m in executables[:5]), ctx.path, executables[0].offset)
    if mime is None:
        yield Finding("values.document-type-missing", Severity.MEDIUM, "Encapsulated document without a MIME type",
                      f"{where} has no MIME Type of Encapsulated Document (0042,0012); viewers must guess how to "
                      "open it", ctx.path, doc.value_offset)
        return
    expected = _EXPECTED.get(mime)
    if expected and (actual is None or actual.signature.kind != expected):
        found = actual.signature.label if actual else signatures.describe(buf, doc.value_offset, doc.end)
        yield Finding("values.document-type-mismatch", Severity.HIGH, "Encapsulated document is not what it claims",
                      f"{where} declares {signatures.printable(mime.encode())} but its content is {found}; "
                      "software that trusts the declared type and software that sniffs the content handle it "
                      "differently", ctx.path, doc.value_offset)
