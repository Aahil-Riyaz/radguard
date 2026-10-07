"""Private data elements: the least-inspected bytes in any DICOM file.

Vendors store their own data in odd-numbered groups (PS3.5 7.8). A Private
Creator element (gggg,00xx) names the implementer and reserves block xx;
the block's data lives at (gggg,xx00-xxFF). Software that does not know the
creator skips the whole block, so private data is where a payload is least
likely to be looked at. This check enforces the reservation rules and looks
inside private values:

* orphan data (no creator reserves its block) cannot be attributed to anyone,
  so every tool ignores it;
* high-entropy blobs that match no known format look like encrypted data;
* zlib and gzip blobs are decompressed under strict budgets and searched,
  because compression hides an executable from any signature search, and
  bytes after the end of a compressed stream are examined too.
"""

from __future__ import annotations

import zlib
from collections import defaultdict
from collections.abc import Generator, Iterator
from dataclasses import dataclass, field

from radguard import signatures
from radguard.carving import carve
from radguard.context import FileContext
from radguard.dicom.model import ITEM, Buffer, Element, tag_str
from radguard.findings import Finding, Severity

ILLEGAL_GROUPS = frozenset({0x0001, 0x0003, 0x0005, 0x0007, 0xFFFF})  # PS3.5 7.8.1
OPAQUE_MIN = 4096  # bytes before a run of private data can be called an opaque blob
OPAQUE_ENTROPY = 7.5  # bits/byte; real compressed or encrypted data sits near 8
SAMPLE = 64 << 10  # bytes used to estimate entropy; pragma: no mutate (tuning)
INFLATE_PER_VALUE = 64 << 20  # decompressed bytes per value; pragma: no mutate (tuning)
INFLATE_PER_FILE = 256 << 20  # decompressed bytes per file, across all values; pragma: no mutate (tuning)
RATIO_LIMIT = 1000  # decompressed/compressed beyond this is a bomb, not data
_BINARY_VRS = frozenset({"OB", "OW", "UN", "OD", "OF", "OL", "OV"})
# Formats that legitimately look random, so their presence explains high entropy.
_KNOWN_DENSE = (b"\xff\xd8\xff", b"\xff\x4f\xff\x51", b"\x00\x00\x00\x0cjP  ", b"\x89PNG", b"PK\x03\x04",
                b"%PDF-", b"7z\xbc\xaf\x27\x1c", b"BZh", b"\xfd7zXZ")


@dataclass
class _Dataset:
    """Private-tag bookkeeping for one dataset (the top level, or one sequence item)."""
    creators: dict[tuple[int, int], Element] = field(default_factory=dict)  # (group, block) -> creator
    data: list[Element] = field(default_factory=list)


@dataclass
class _Budget:
    remaining: int  # decompressed bytes this file may still produce


def check(ctx: FileContext) -> Iterator[Finding]:
    parsed = ctx.parsed
    datasets: dict[tuple[str, int | None], _Dataset] = defaultdict(_Dataset)
    for el in parsed.elements:
        group, elem = el.tag >> 16, el.tag & 0xFFFF
        if el.tag == ITEM or not group % 2:
            continue
        if group in ILLEGAL_GROUPS:
            yield Finding("private.illegal-group", Severity.MEDIUM, "Private element in a forbidden group",
                          f"{tag_str(el.tag)}: groups 0001, 0003, 0005, 0007 and FFFF may not carry private data "
                          "(PS3.5 7.8.1); readers disagree on whether they are standard or private",
                          ctx.path, el.offset)
        ds = datasets[(el.domain, el.parent)]
        if 0x0010 <= elem <= 0x00FF:
            ds.creators.setdefault((group, elem), el)
        elif elem >= 0x1000:
            ds.data.append(el)
        elif elem:  # (gggg,0000) is a retired group length; everything else here belongs to no block
            yield Finding("private.unusable-element", Severity.MEDIUM, "Private element outside any reservable block",
                          f"{tag_str(el.tag)}: only (gggg,0010-00FF) creators and (gggg,1000-FFFF) data elements are "
                          "defined (PS3.5 7.8.1), so no reader can interpret this one", ctx.path, el.offset)

    budget = _Budget(INFLATE_PER_FILE)  # read at scan time, so the limit stays configurable
    for (domain, _), ds in datasets.items():
        buf = parsed.buffer(domain, ctx.buf)
        yield from _creators(ctx.path, buf, ds)
        for el in ds.data:
            group, block = el.tag >> 16, (el.tag & 0xFFFF) >> 8
            creator = ds.creators.get((group, block))
            if creator is None:
                yield Finding(
                    "private.orphan-element", Severity.MEDIUM, "Private data with no creator",
                    f"{tag_str(el.tag)} ({el.end - el.value_offset:,} bytes) sits in block {block:02X} of group "
                    f"{group:04X}, but no Private Creator ({group:04X},00{block:02X}) reserves it; no software can "
                    "attribute it, so every tool ignores it", ctx.path, el.offset,
                )
            if el.vr in _BINARY_VRS and el.fragments is None:
                where = f"{tag_str(el.tag)} [{_name(buf, creator)}]"
                yield from _blob(ctx.path, buf, el, where, budget)


def _creators(path: str, buf: Buffer, ds: _Dataset) -> Iterator[Finding]:
    seen: dict[tuple[int, bytes], Element] = {}
    for (group, _), el in sorted(ds.creators.items()):
        value = bytes(buf[el.value_offset : el.end]).rstrip(b" \x00")
        problem = None
        if not value:
            problem = "is empty"
        elif el.vr_source == "explicit" and el.vr != "LO":
            problem = f"is encoded as {el.vr}; Private Creator values are LO"
        elif any(b < 0x20 or b == 0x7F for b in value) or len(value) > 64:
            problem = "contains control characters or exceeds 64 characters, which LO does not allow"
        if problem:
            yield Finding("private.creator-invalid", Severity.LOW, "Malformed Private Creator",
                          f"{tag_str(el.tag)} {problem}; readers that match creators by value cannot recognise the "
                          "block", path, el.offset)
        key = (group, value)
        if value and key in seen:
            yield Finding("private.duplicate-creator", Severity.LOW, "Private Creator reserves two blocks",
                          f"{signatures.printable(value)!r} reserves both {tag_str(seen[key].tag)} and "
                          f"{tag_str(el.tag)}; readers that look a creator up by name find one block or the other",
                          path, el.offset)
        seen.setdefault(key, el)


def _blob(path: str, buf: Buffer, el: Element, where: str, budget: _Budget) -> Iterator[Finding]:
    start, end = el.value_offset, el.end
    kind = _compression(bytes(buf[start : start + 4]))  # pragma: no mutate (equivalent: window > longest header)
    if kind is not None:
        inflated = yield from _inflate(path, buf, el, where, kind, budget)
        if inflated is not None:
            start = end - inflated  # bytes after the stream are judged on their own below
            if start == end:
                return
    yield from _opaque(path, buf, start, end, where, after_stream=start != el.value_offset)


def _compression(head: bytes) -> str | None:
    if head.startswith(b"\x1f\x8b\x08"):
        return "gzip"
    # zlib (RFC 1950): CM = 8 (deflate), CINFO <= 7, and the header checksum must divide by 31. This is a
    # pre-filter that saves trying to inflate every value; inflate validates the header itself, and a
    # value that does not inflate is judged as raw bytes.
    if (len(head) >= 2 and head[0] & 0x0F == 8 and head[0] >> 4 <= 7  # pragma: no mutate (equivalent: pre-filter)
            and (head[0] << 8 | head[1]) % 31 == 0):  # pragma: no mutate (equivalent: pre-filter)
        return "zlib"
    return None


def _inflate(path: str, buf: Buffer, el: Element, where: str, kind: str,
             budget: _Budget) -> Generator[Finding, None, int | None]:
    """Decompress and search a private value. Returns how many bytes follow the end of the
    compressed stream, or None if the value was not really compressed (a coincidental header)."""
    compressed = bytes(buf[el.value_offset : el.end])
    per_value = min(INFLATE_PER_VALUE, len(compressed) * RATIO_LIMIT)
    limit = min(per_value, budget.remaining)
    # zlib treats max_length=0 as "no limit": never pass it. Any positive limit is bounded.
    if limit < 1:  # pragma: no mutate (equivalent: any positive limit is bounded)
        yield _bomb(path, el, where, kind, len(compressed), "the per-file decompression budget is spent")
        return 0  # pragma: no mutate (equivalent: under the 16-byte reporting floor)
    gzip_wbits = 16 + zlib.MAX_WBITS  # pragma: no mutate (equivalent: 32 + MAX_WBITS also accepts gzip)
    inflater = zlib.decompressobj(gzip_wbits if kind == "gzip" else zlib.MAX_WBITS)
    try:
        data = inflater.decompress(compressed, limit)
    except zlib.error:
        return None  # not compressed after all; the caller judges the bytes as they are
    budget.remaining -= len(data)
    if not inflater.eof and len(data) >= limit:  # input left over always means the output hit the limit
        reason = (f"it expands more than {RATIO_LIMIT}:1" if limit == len(compressed) * RATIO_LIMIT
                  else "the per-file decompression budget is spent" if limit < per_value
                  else f"it expands beyond {limit:,} bytes")
        yield _bomb(path, el, where, kind, len(compressed), reason)
    index = carve(data)
    if index.matches:
        top = max(index.matches, key=lambda m: m.signature.severity)
        yield Finding(
            "private.compressed-payload", max(Severity.HIGH, top.signature.severity),
            f"{top.signature.label} hidden inside compressed private data",
            f"{where} is {kind}-compressed; after decompression it contains "
            + ", ".join(f"{m.signature.label} at decompressed offset {m.offset:#x}"
                        for m in index.matches[:5])  # pragma: no mutate (display)
            + ". Compression hides it from any signature search of the file itself", path, el.value_offset,
        )
    for gap in index.exhausted:
        if gap.reason != "size":
            yield Finding("private.analysis-incomplete", Severity.HIGH,
                          "Compressed private data built to exhaust analysis",
                          f"{where}: {gap.detail} (decompressed offset {gap.offset:#x})", path, el.value_offset)
    return len(inflater.unused_data) if inflater.eof else 0  # pragma: no mutate (equivalent: under the reporting floor)


def _bomb(path: str, el: Element, where: str, kind: str, size: int, reason: str) -> Finding:
    return Finding(
        "private.decompression-bomb", Severity.HIGH, "Compressed private data too large to inspect",
        f"{where} is {kind} data ({size:,} compressed bytes) that was not fully inspected because {reason}; "
        "a decompression bomb, or data built to exceed analysis budgets", path, el.value_offset,
    )


def _opaque(path: str, buf: Buffer, start: int, end: int, where: str, *, after_stream: bool) -> Iterator[Finding]:
    size = end - start
    if after_stream and size >= 16:
        yield Finding(
            "private.data-after-stream", Severity.MEDIUM, "Data hidden after a compressed stream",
            f"{where}: {size:,} bytes follow the end of the compressed stream; decompressors stop at the end, so "
            f"nothing that reads the value normally sees them; {signatures.describe(buf, start, end)}", path, start,
        )
        return
    head = bytes(buf[start : start + 16])  # pragma: no mutate (equivalent: window > longest dense magic)
    if size < OPAQUE_MIN or head.startswith(_KNOWN_DENSE):
        return
    entropy = signatures.entropy(bytes(buf[start : start + min(size, SAMPLE)]))
    if entropy >= OPAQUE_ENTROPY:
        yield Finding(
            "private.opaque-blob", Severity.MEDIUM, "High-entropy private data of unknown format",
            f"{where} holds {size:,} bytes at {entropy:.2f} bits/byte matching no known format; that is how "
            "encrypted or compressed data looks, and nothing in the file explains it", path, start,
        )


def _name(buf: Buffer, creator: Element | None) -> str:
    if creator is None:
        return "no creator"
    name = bytes(buf[creator.value_offset : creator.end]).rstrip(b" \x00")
    return signatures.printable(name, 48)  # pragma: no mutate (display)
