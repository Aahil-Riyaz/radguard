"""Encapsulated (compressed) Pixel Data: frames, codestreams and the bytes after them.

Compressed frames are split into fragments. This check reassembles frames the
way decoders do, follows each codec's marker structure to the frame's true
end (radguard.codecs), and reports:

* bytes after the end of a codestream: decoders stop at the end marker, so
  anything after it is never displayed (a second image, an executable, ...);
* frames that do not start like the transfer syntax's codec at all;
* malformed codestreams, the input class behind many decoder memory-safety bugs;
* more or fewer frames than the header declares.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator

from radguard import codecs, signatures
from radguard.context import FileContext
from radguard.dicom import values
from radguard.dicom.model import PIXEL_DATA, Element
from radguard.findings import Finding, Severity

NUMBER_OF_FRAMES = 0x00280008
MAX_FRAME_BYTES = 256 << 20  # reassembled per file; the rest is reported as not inspected

_JPEG = ("1.2.840.10008.1.2.4.50", "1.2.840.10008.1.2.4.51", "1.2.840.10008.1.2.4.57", "1.2.840.10008.1.2.4.70")
_JPEG_LS = ("1.2.840.10008.1.2.4.80", "1.2.840.10008.1.2.4.81")
_J2K = ("1.2.840.10008.1.2.4.90", "1.2.840.10008.1.2.4.91", "1.2.840.10008.1.2.4.92",
        "1.2.840.10008.1.2.4.93", "1.2.840.10008.1.2.4.201", "1.2.840.10008.1.2.4.202",
        "1.2.840.10008.1.2.4.203")
_RLE = ("1.2.840.10008.1.2.5",)
CODECS = {**dict.fromkeys(_JPEG, "jpeg"), **dict.fromkeys(_JPEG_LS, "jpeg-ls"),
          **dict.fromkeys(_J2K, "j2k"), **dict.fromkeys(_RLE, "rle")}
_FRAME_START = {"jpeg": b"\xff\xd8", "jpeg-ls": b"\xff\xd8", "j2k": b"\xff\x4f\xff\x51"}
_IMAGE_STARTS = (b"\xff\xd8\xff", b"\xff\x4f\xff\x51", b"\x89PNG\r\n\x1a\n")


def check(ctx: FileContext) -> Iterator[Finding]:
    parsed = ctx.parsed
    codec = CODECS.get(parsed.syntax.uid or "")
    domain = parsed.dataset_domain
    buf = parsed.buffer(domain, ctx.buf)
    top: dict[int, list[Element]] = defaultdict(list)
    for el in parsed.elements:
        if el.depth == 0 and el.domain == domain:
            top[el.tag].append(el)
    pixels = [px for px in top.get(PIXEL_DATA, []) if px.fragments is not None]
    if codec is None or not pixels:
        return
    declared = values.number(buf, top[NUMBER_OF_FRAMES][0]) if top.get(NUMBER_OF_FRAMES) else 1
    declared = declared if declared and declared > 0 else 1

    budget = MAX_FRAME_BYTES
    for px in pixels:
        frames = _frames(buf, px, codec, declared)
        if len(frames) > declared:
            yield Finding("pixels.hidden-frames", Severity.HIGH, f"{len(frames) - declared} undeclared frame(s)",
                          f"Pixel Data holds {len(frames)} frames but Number of Frames is {declared}; decoders that "
                          "trust the header show fewer frames than decoders that walk the fragments",
                          ctx.path, px.offset)
        elif len(frames) < declared:
            yield Finding("pixels.missing-frames", Severity.MEDIUM, "Fewer frames than declared",
                          f"Number of Frames is {declared} but Pixel Data holds {len(frames)}", ctx.path, px.offset)
        for number, frags in enumerate(frames, 1):
            size = sum(n for _, n in frags)
            if size > budget:
                yield Finding("pixels.analysis-incomplete", Severity.LOW, "Frames beyond the inspection budget",
                              f"frame {number} onwards ({size:,} bytes) was not reassembled", ctx.path, frags[0][0])
                return
            budget -= size
            yield from _frame(ctx, buf, domain, codec, number, frags)


def _frames(buf, px: Element, codec: str, declared: int) -> list[list[tuple[int, int]]]:
    """Group fragments into frames the way decoders do (PS3.5 A.4)."""
    frags = px.fragments
    if not frags:
        return []
    if len(frags) == declared:
        return [[f] for f in frags]
    if declared == 1:
        return [frags]
    start = _FRAME_START.get(codec)
    if start is None:
        return [[f] for f in frags]
    frames: list[list[tuple[int, int]]] = []
    for offset, length in frags:
        if not frames or bytes(buf[offset : offset + len(start)]) == start:
            frames.append([])
        frames[-1].append((offset, length))
    return frames


def _frame(ctx: FileContext, buf, domain: str, codec: str, number: int,
           frags: list[tuple[int, int]]) -> Iterator[Finding]:
    data = b"".join(bytes(buf[o : o + n]) for o, n in frags)
    first = frags[0][0]
    if codec == "rle":
        problem = codecs.rle_problem(data)
        if problem:
            yield Finding("pixels.malformed-codestream", Severity.MEDIUM, "Malformed RLE frame",
                          f"frame {number}: {problem}", ctx.path, first)
        return

    expected = _FRAME_START[codec]
    if not data.startswith(expected):
        actual = signatures.match_prefix(data, 0, len(data))
        what = actual.signature.label if actual else signatures.describe(data, 0, len(data))
        severity = Severity.CRITICAL if actual and actual.signature.severity is Severity.CRITICAL else Severity.HIGH
        yield Finding("pixels.codec-mismatch", severity, "Frame is not the codec its transfer syntax declares",
                      f"frame {number} should start with {expected.hex(' ')} ({codec}) but is {what}",
                      ctx.path, first)
        return

    end, problem = codecs.j2k_end(data) if codec == "j2k" else codecs.jpeg_end(data, ls=codec == "jpeg-ls")
    if end is None:
        yield Finding("pixels.malformed-codestream", Severity.MEDIUM, "Malformed compressed frame",
                      f"frame {number}: {problem}; malformed codestreams are the input class behind many image "
                      "decoder memory-safety bugs", ctx.path, first)
        return
    trailing = data[end:]
    if len(trailing) <= 1 and not any(trailing):  # fragments are even-length: one zero pad byte is legal
        return
    start = _file_offset(frags, end)
    hits = [m for o, n in frags for m in ctx.matches(domain).within(max(o, start), o + n)]
    found = [p for p in (trailing.find(magic) for magic in _IMAGE_STARTS) if p != -1]  # C-speed, not a byte loop
    image_at = min(found) if found else None
    if hits:
        severity = max(Severity.HIGH, *(m.signature.severity for m in hits))
    else:
        severity = Severity.HIGH if image_at is not None or len(trailing) >= 64 else Severity.MEDIUM
    detail = (f"frame {number}'s codestream ends at frame offset {end:#x} but the frame continues for "
              f"{len(trailing):,} more bytes; decoders stop at the end marker, so these bytes are never displayed")
    if image_at is not None:
        detail += f"; a second image starts {image_at:,} bytes after the end"
    if hits:
        detail += "; contains " + ", ".join(signatures.match_text(m) for m in hits[:5])
    detail += "; " + signatures.describe(trailing, 0, len(trailing))
    title = ("Second image hidden after the end of a frame" if image_at is not None and not hits
             else f"{len(trailing):,} bytes hidden after the end of a compressed frame")
    yield Finding("pixels.codestream-trailing-data", severity, title, detail, ctx.path, start)


def _file_offset(frags: list[tuple[int, int]], relative: int) -> int:
    for offset, length in frags:
        if relative < length:
            return offset + relative
        relative -= length
    return frags[-1][0] + frags[-1][1]
