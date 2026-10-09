"""Property-based fuzzing: hostile input must never crash the scanner or break byte accounting.

Invariants, for any input:
  1. parsing and every check terminate without raising;
  2. coverage regions lie inside the buffer and never overlap;
  3. explained + unexplained bytes == file size, exactly;
  4. every element's offsets are ordered and in bounds.
"""

import struct

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from builder import (
    DEFLATED_LE, EXPLICIT_BE, EXPLICIT_LE, IMPLICIT_LE, JPEG_BASELINE, deflate, el, encapsulated, even,
    fake_elf, fake_pe, image, item, j2k, jpeg, part10, rle_frame, seq,
)
from radguard.codecs import j2k_end, jpeg_end, rle_problem
from radguard.checks import ALL_CHECKS
from radguard.context import FileContext
from radguard.dicom import Limits, coverage, parse
from radguard.findings import FILE, INFLATED
from radguard.rules import RULES

HEADER = bytes(128) + b"DICM"
LIMITS = Limits(max_depth=8, max_elements=5_000, max_inflated=1 << 20)

CORPUS = [
    part10(image(4, 4)),
    part10(image(4, 4, implicit=True), ts=IMPLICIT_LE),
    part10(image(4, 4, little=False), ts=EXPLICIT_BE),
    part10(deflate(image(4, 4)), ts=DEFLATED_LE),
    part10(image(4, 4, pixel_element=encapsulated(bytes(10), bytes(6), bot=struct.pack("<2I", 0, 18))),
           ts=JPEG_BASELINE),
    part10(seq(0x00081140, item(seq(0x00081150, item(el(0x00081155, "UI", "1.2")), undefined=True),
                                undefined=True), item(b"")) + el(0xFFFCFFFC, "OB", fake_pe(96))),
    part10(el(0x00091010, "UN", item(el(0x00100010, "PN", "X", implicit=True)))),
    part10(image(8, 8, pixel_element=encapsulated(even(jpeg()), even(jpeg() + fake_pe()))), ts=JPEG_BASELINE),
    part10(image(8, 8, pixel_element=encapsulated(even(j2k()))), ts="1.2.840.10008.1.2.4.90"),
    part10(image(8, 8, pixel_element=encapsulated(rle_frame(2))), ts="1.2.840.10008.1.2.5"),
    part10(el(0x00420011, "OB", even(b"%PDF-1.7\n%%EOF")) + el(0x00420012, "LO", "application/pdf")
           + el(0x00291010, "OB", fake_elf())),
]


def check_invariants(data: bytes) -> None:
    parsed = parse(data, LIMITS)
    for regions, size in ((parsed.regions, len(data)),
                          (parsed.inflated_regions, len(parsed.inflated or b""))):
        ordered = sorted(regions)
        for start, end, _ in ordered:
            assert 0 <= start < end <= size
        for (_, end1, _), (start2, _, _) in zip(ordered, ordered[1:]):
            assert end1 <= start2, "overlapping regions"
        explained = sum(end - start for start, end, _ in regions)
        assert explained + sum(end - start for start, end in coverage.gaps(regions, size)) == size
    for el_ in parsed.elements:
        limit = len(data) if el_.domain == "file" else len(parsed.inflated)
        assert el_.offset <= el_.value_offset <= el_.end <= limit
    ctx = FileContext("<fuzz>", data, len(data))
    ctx.__dict__["parsed"] = parsed  # reuse the bounded parse
    sizes = {FILE: len(data), INFLATED: len(parsed.inflated) if parsed.inflated is not None else -1}
    for check in ALL_CHECKS:
        for finding in check(ctx):
            assert finding.check in RULES and finding.title  # every finding is a catalogued rule
            # ...and points inside the bytes its offset counts: the file, or the decompressed dataset.
            assert finding.offset is None or 0 <= finding.offset <= sizes[finding.domain], finding


# Example counts come from the Hypothesis profile (see conftest.py): 400 by default,
# HYPOTHESIS_PROFILE=deep for a long run.
fuzz = settings(deadline=None, suppress_health_check=[HealthCheck.too_slow])


@fuzz
@given(st.binary(max_size=600))
def test_arbitrary_bytes_after_magic(tail):
    check_invariants(HEADER + tail)


@fuzz
@given(st.binary(max_size=400), st.sampled_from([EXPLICIT_LE, IMPLICIT_LE, EXPLICIT_BE, DEFLATED_LE, JPEG_BASELINE]))
def test_arbitrary_dataset_behind_valid_meta(tail, ts):
    check_invariants(part10(tail, ts=ts))


@fuzz
@given(st.data())
def test_mutated_valid_files(data):
    blob = bytearray(data.draw(st.sampled_from(CORPUS)))
    for _ in range(data.draw(st.integers(1, 12))):
        pos = data.draw(st.integers(132, len(blob) - 1))
        blob[pos] = data.draw(st.integers(0, 255))
    if data.draw(st.booleans()):
        del blob[data.draw(st.integers(132, len(blob))):]
    check_invariants(bytes(blob))


@fuzz
@given(st.data())
def test_spliced_lengths(data):
    # Lengths are what parsers trust most; overwrite 4-byte windows with extreme values.
    blob = bytearray(data.draw(st.sampled_from(CORPUS)))
    for _ in range(data.draw(st.integers(1, 4))):
        pos = data.draw(st.integers(132, len(blob) - 4))
        value = data.draw(st.sampled_from([0, 1, 2, 0x7FFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, len(blob)]))
        struct.pack_into("<I", blob, pos, value)
    check_invariants(bytes(blob))


CODESTREAMS = [jpeg(), jpeg(app1=b"Exif\x00\x00" + jpeg()), j2k(), j2k(psot_zero=True), rle_frame(3)]


def check_walkers(data: bytes) -> None:
    for end, problem in (jpeg_end(data), jpeg_end(data, ls=True), j2k_end(data)):
        assert (end is None) != (problem is None)
        assert end is None or 2 <= end <= len(data)
    rle_problem(data)


@fuzz
@given(st.binary(max_size=400))
def test_codec_walkers_on_arbitrary_bytes(data):
    check_walkers(data)
    check_walkers(b"\xff\xd8" + data)
    check_walkers(b"\xff\x4f\xff\x51" + data)


@fuzz
@given(st.data())
def test_codec_walkers_on_mutated_codestreams(data):
    blob = bytearray(data.draw(st.sampled_from(CODESTREAMS)))
    for _ in range(data.draw(st.integers(1, 8))):
        blob[data.draw(st.integers(0, len(blob) - 1))] = data.draw(st.integers(0, 255))
    check_walkers(bytes(blob[: data.draw(st.integers(0, len(blob)))]))
