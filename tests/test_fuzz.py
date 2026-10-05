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
    DEFLATED_LE, EXPLICIT_BE, EXPLICIT_LE, IMPLICIT_LE, JPEG_BASELINE, deflate, el, encapsulated,
    fake_pe, image, item, part10, seq,
)
from radguard.checks import ALL_CHECKS
from radguard.context import FileContext
from radguard.dicom import Limits, coverage, parse

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
    for check in ALL_CHECKS:
        for finding in check(ctx):
            assert finding.check and finding.title


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
