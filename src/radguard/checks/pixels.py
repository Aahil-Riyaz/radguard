"""Pixel Data consistency: what the header promises versus what the bytes contain.

Viewers render exactly Rows x Columns x Frames pixels and nothing else, so the
image header is a contract. Breaking it in one direction hides data (slack
after the last pixel); in the other it makes decoders read or write outside
their buffers; and two copies of the image let different software show
different pictures from the same file.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator

from radguard import signatures
from radguard.carving import MatchIndex
from radguard.context import FileContext
from radguard.dicom import values
from radguard.dicom.model import DOUBLE_PIXEL_DATA, FLOAT_PIXEL_DATA, PIXEL_DATA, Buffer, Element, ParsedFile
from radguard.findings import Finding, Severity

SAMPLES_PER_PIXEL, NUMBER_OF_FRAMES = 0x00280002, 0x00280008
ROWS, COLUMNS, BITS_ALLOCATED = 0x00280010, 0x00280011, 0x00280100
_GEOMETRY = {ROWS: "Rows", COLUMNS: "Columns", SAMPLES_PER_PIXEL: "Samples per Pixel",
             NUMBER_OF_FRAMES: "Number of Frames", BITS_ALLOCATED: "Bits Allocated"}


def check(ctx: FileContext) -> Iterator[Finding]:
    parsed = ctx.parsed
    domain = parsed.dataset_domain
    buf = parsed.buffer(domain, ctx.buf)
    top: dict[int, list[Element]] = defaultdict(list)
    for el in parsed.elements:
        if el.depth == 0 and el.domain == domain:
            top[el.tag].append(el)

    pixels = top.get(PIXEL_DATA, [])
    if len(pixels) > 1:
        where = ", ".join(f"{px.offset:#x}" for px in pixels)
        yield Finding(
            "pixels.duplicate-pixel-data", Severity.CRITICAL, "Two images in one file",
            f"{len(pixels)} Pixel Data elements at {where}. Software that keeps the first copy and software "
            "that keeps the last display different images from the same file, so a radiologist's viewer and "
            "an AI pipeline can be shown different scans",
            ctx.path, pixels[1].offset, domain=domain,
        )
    floats = top.get(FLOAT_PIXEL_DATA, []) + top.get(DOUBLE_PIXEL_DATA, [])
    if pixels and floats:
        yield Finding(
            "pixels.multiple-representations", Severity.HIGH, "Integer and float pixel data in one file",
            "the dataset carries both Pixel Data and (Double) Float Pixel Data; which one is displayed "
            "depends on the software", ctx.path, floats[0].offset, domain=domain,
        )
    if not pixels:
        return

    for tag, name in _GEOMETRY.items():
        copies = top.get(tag, [])
        seen = [values.number(buf, el) for el in copies]
        if len(set(seen)) > 1:
            yield Finding(
                "pixels.ambiguous-geometry", Severity.HIGH, f"Conflicting {name} values",
                f"{name} appears {len(copies)} times with different values ({', '.join(map(str, seen))}); readers "
                "that keep the first copy and readers that keep the last decode the same pixel bytes with different "
                "dimensions. Size checks below use the first", ctx.path, copies[1].offset, domain=domain,
            )

    def first(tag: int) -> int | None:
        return values.number(buf, top[tag][0]) if top.get(tag) else None

    geometry = (first(ROWS), first(COLUMNS), first(SAMPLES_PER_PIXEL) or 1,
                first(NUMBER_OF_FRAMES) or 1, first(BITS_ALLOCATED))
    for px in pixels:
        yield from _check_pixel_data(ctx.path, buf, parsed, ctx.matches(domain), px, *geometry)


def _check_pixel_data(path: str, buf: Buffer, parsed: ParsedFile, index: MatchIndex, px: Element,
                      rows: int | None, cols: int | None, samples: int, frames: int,
                      bits: int | None) -> Iterator[Finding]:
    if px.undefined != parsed.syntax.encapsulated:
        expected_form = "encapsulated" if parsed.syntax.encapsulated else "native"
        actual_form = "encapsulated" if px.undefined else "native"
        yield Finding(
            "pixels.encoding-mismatch", Severity.HIGH, "Pixel Data encoding contradicts the transfer syntax",
            f"{parsed.syntax.name} requires {expected_form} Pixel Data but this element is {actual_form}; "
            "decoders take different code paths for the same bytes", path, px.offset, domain=px.domain,
        )
    if px.undefined or rows is None or cols is None or bits is None:
        return

    shape = f"{rows}x{cols}, {samples} sample(s), {frames} frame(s), {bits}-bit"
    if min(rows, cols, samples, frames, bits) <= 0:
        # Number of Frames is text (IS), so "0" or "-5" is easy to write; decoders disagree on what to render.
        yield Finding(
            "pixels.invalid-geometry", Severity.MEDIUM, "Image header declares a zero or negative dimension",
            f"{shape}; decoders disagree on what, if anything, to render", path, px.offset, domain=px.domain,
        )
        return
    expected = (rows * cols * samples * frames * bits + 7) // 8
    if expected >= 1 << 32:
        yield Finding(
            "pixels.size-overflow", Severity.HIGH, "Image size overflows 32-bit arithmetic",
            f"{shape} needs {expected:,} bytes. A decoder that computes the size in 32 bits allocates "
            f"{expected % (1 << 32):,} bytes and then writes the full image: a heap overflow",
            path, px.offset, domain=px.domain,
        )
        return

    actual = px.end - px.value_offset
    padded = expected + (expected & 1)  # one pad byte keeps the value even-length
    inside = index.within(px.value_offset, px.value_offset + min(actual, padded))
    if inside:
        # Validated signatures make chance matches in real pixel data vanishingly rare.
        listed = ", ".join(signatures.match_text(m) for m in inside[:5])  # pragma: no mutate (display)
        yield Finding(
            "pixels.embedded-file", max(m.signature.severity for m in inside),
            f"{inside[0].signature.label} stored as image pixels",
            f"the declared image area contains {listed}; viewers render it as noise, and nothing that only "
            "displays images will notice", path, inside[0].offset, domain=px.domain,
        )
    if actual < expected:
        yield Finding(
            "pixels.truncated", Severity.HIGH, "Pixel Data shorter than the image it describes",
            f"{shape} needs {expected:,} bytes but Pixel Data holds {actual:,}; decoders that trust the header "
            f"read {expected - actual:,} bytes past the end of the buffer", path, px.offset, domain=px.domain,
        )
    elif actual > padded:
        start, n = px.value_offset + padded, actual - padded
        frame_bytes = expected // frames
        hidden_frames = n // frame_bytes if frame_bytes else 0
        hits = index.within(start, px.end)
        sample = bytes(buf[start : start + min(n, 4096)])  # pragma: no mutate (tuning)
        if hits:
            severity = max(Severity.HIGH, *(m.signature.severity for m in hits))
        elif hidden_frames or n >= 4096 or (n >= 256 and signatures.entropy(sample) > 7.0):
            severity = Severity.HIGH
        else:
            severity = Severity.MEDIUM
        detail = (f"Pixel Data is {actual:,} bytes but {shape} needs only {expected:,}. The {n:,} bytes from "
                  f"{start:#x} are outside the image the header describes: viewers that honour the header "
                  "never display them, while lenient decoders return them as extra frames")
        if hits:
            listed = ", ".join(signatures.match_text(m) for m in hits[:5])  # pragma: no mutate (display)
            detail += f"; contains {listed}"
        detail += "; " + signatures.describe(buf, start, px.end)
        title = (f"{hidden_frames} hidden frame(s) after the declared image" if hidden_frames
                 else f"{n:,} bytes hidden after the last pixel")
        yield Finding("pixels.slack", severity, title, detail, path, start, domain=px.domain)
