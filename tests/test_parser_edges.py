"""Parser edges, written against surviving mutants: exact limits, recovery, and sniffing."""

import struct

import pytest

from builder import (
    DEFLATED_LE, EXPLICIT_LE, IMPLICIT_LE, JPEG_BASELINE, PIXEL_DATA, UNDEF, deflate, el, encapsulated, image, item,
    part10, seq, seq_delim, tag, us,
)
from radguard.dicom import Limits, coverage, looks_like_dataset, parse
from radguard.dicom.model import ITEM
from radguard.dicom.parser import _Parser, _Tally
from test_anomalies import CASES

STOPPING = {"invalid-vr", "length-overflow", "truncated-header", "stray-delimiter", "bad-sequence-item",
            "undefined-length-invalid", "max-depth", "element-limit", "deflate-error", "bad-fragment-item",
            "undefined-fragment-length"}


def codes(data: bytes, **kwargs) -> list[str]:
    return [a.code for a in parse(data, **kwargs).anomalies]


# -- recovery: a stop leaves the rest unexplained, exactly from where it stopped -------------------

EXTRA_STOPS = [
    ("length-overflow", part10(el(0x00081140, "SQ", struct.pack("<HHI", 0xFFFE, 0xE000, 999) + b"abcd")), {}),
    ("length-overflow", part10(el(PIXEL_DATA, "OB", item(b"") + struct.pack("<HHI", 0xFFFE, 0xE000, 99) + b"ab",
                                  length=UNDEF), ts=JPEG_BASELINE), {}),
    ("truncated-header", part10(el(0x00081140, "SQ", item(b"") + b"\xfe\xff")), {}),
]


@pytest.mark.parametrize("code,data,kwargs", [c for c in CASES if c[0] in STOPPING] + EXTRA_STOPS,
                         ids=[c[0] for c in CASES if c[0] in STOPPING] + [f"extra-{c[0]}" for c in EXTRA_STOPS])
def test_every_stop_leaves_the_remainder_unexplained(code, data, kwargs):
    parsed = parse(data, **kwargs)
    starts = {start for start, _ in coverage.gaps(parsed.regions, parsed.size)}
    if parsed.inflated is not None:
        starts |= {start for start, _ in coverage.gaps(parsed.inflated_regions, len(parsed.inflated))}
    stops = [a for a in parsed.anomalies if a.code == code]
    assert stops and all(a.offset in starts for a in stops), (code, [a.offset for a in stops], sorted(starts))


def test_unterminated_pixel_data_with_leftover_bytes_stops():
    data = part10(el(PIXEL_DATA, "OB", item(b"") + item(b"ab") + b"xyz", length=UNDEF), ts=JPEG_BASELINE)
    assert coverage.gaps(parse(data).regions, len(data)) == [(len(data) - 3, len(data))]


def test_stray_delimiter_stops_even_before_valid_data():
    for delimiter in (0xE00D, 0xE0DD):
        data = part10(struct.pack("<HHI", 0xFFFE, delimiter, 0) + el(0x00100010, "PN", "AFTER"))
        parsed = parse(data)
        assert [a.code for a in parsed.anomalies] == ["stray-delimiter"]
        assert not any(e.tag == 0x00100010 for e in parsed.elements)


def test_unterminated_undefined_item_is_reported_once():
    data = part10(el(0x00081140, "SQ", struct.pack("<HHI", 0xFFFE, 0xE000, UNDEF) + el(0x00100010, "PN", "X"),
                     length=UNDEF))
    assert codes(data).count("missing-item-delimiter") == 1 and "missing-sequence-delimiter" in codes(data)
    closed_by_sequence = part10(el(0x00081140, "SQ", struct.pack("<HHI", 0xFFFE, 0xE000, UNDEF) + seq_delim(),
                                   length=UNDEF))
    assert codes(closed_by_sequence) == ["missing-item-delimiter"]


# -- exact limits ------------------------------------------------------------------------------

def test_part10_regions_are_exact():
    parsed = parse(part10())
    assert parsed.regions[:2] == [(0, 128, "preamble"), (128, 132, "magic")]


@pytest.mark.parametrize("vr,size", [("US", 2), ("SS", 2), ("UL", 4), ("SL", 4), ("FL", 4), ("AT", 4),
                                     ("FD", 8), ("SV", 8), ("UV", 8)])
def test_fixed_size_vr_lengths(vr, size):
    assert "vr-length-mismatch" not in codes(part10(el(0x00091010, vr, bytes(2 * size))))
    assert "vr-length-mismatch" in codes(part10(el(0x00091010, vr, bytes(size + (1 if size == 2 else 2)))))


@pytest.mark.parametrize("kwargs,ok", [
    ({"max_depth": 1}, True), ({"max_depth": 128}, True), ({"max_depth": 0}, False), ({"max_depth": 129}, False),
    ({"max_elements": 1}, True), ({"max_elements": 0}, False), ({"max_inflated": 0}, True),
    ({"max_inflated": -1}, False),
], ids=["depth1", "depth128", "depth0", "depth129", "elements1", "elements0", "inflated0", "inflated-1"])
def test_limits_validation_edges(kwargs, ok):
    if ok:
        Limits(**kwargs)
    else:
        with pytest.raises(ValueError):
            Limits(**kwargs)


def test_depth_limit_is_inclusive():
    def nested(levels):
        payload = el(0x00100010, "PN", "X")
        for _ in range(levels):
            payload = seq(0x00081140, item(payload, undefined=True), undefined=True)
        return part10(payload)

    assert "max-depth" not in codes(nested(3), limits=Limits(max_depth=3))
    assert "max-depth" in codes(nested(4), limits=Limits(max_depth=3))


def test_padding_bytes_are_counted_as_padding():
    data = part10(image(4, 4) + el(0xFFFCFFFC, "OB", bytes(8)))
    assert coverage.summary(parse(data).regions, len(data))["padding"] == 8


# -- missing or contradictory File Meta ----------------------------------------------------------

def test_part10_file_without_file_meta_is_still_parsed():
    data = bytes(128) + b"DICM" + image(4, 4)
    parsed = parse(data)
    assert {"missing-meta-group-length", "missing-transfer-syntax"} <= {a.code for a in parsed.anomalies}
    assert parsed.syntax.uid is None and any(e.tag == PIXEL_DATA for e in parsed.elements)


def test_part10_file_without_file_meta_and_implicit_data_is_sniffed():
    data = bytes(128) + b"DICM" + image(4, 4, implicit=True)
    parsed = parse(data)
    assert "transfer-syntax-mismatch" in {a.code for a in parsed.anomalies}
    assert coverage.gaps(parsed.regions, len(data)) == []


def test_declared_implicit_but_actually_explicit_is_detected():
    # The implicit reading of this first element ("US" + length 2 read as a 32-bit length,
    # 152,405 bytes) fits in the file, so only the dictionary check exposes it.
    dataset = us(0x00280010, 4) + el(0x00291010, "OB", bytes(160_000))
    parsed = parse(part10(dataset, ts=IMPLICIT_LE))
    assert "transfer-syntax-mismatch" in {a.code for a in parsed.anomalies}
    rows = next(e for e in parsed.elements if e.tag == 0x00280010)
    assert rows.vr == "US" and rows.vr_source == "explicit"


def test_deflated_file_with_no_dataset_is_clean():
    assert codes(part10(ts=DEFLATED_LE)) == []


def test_inflated_dataset_is_fully_explained():
    parsed = parse(part10(deflate(image(4, 4)), ts=DEFLATED_LE))
    assert coverage.gaps(parsed.inflated_regions, len(parsed.inflated)) == []


# -- bare datasets -------------------------------------------------------------------------------

def test_bare_dataset_anomaly_points_at_byte_zero():
    [anomaly] = [a for a in parse(image(4, 4), part10=False).anomalies if a.code == "no-part10-header"]
    assert anomaly.offset == 0


def test_bare_big_endian_dataset_is_detected():
    parsed = parse(image(4, 4, little=False), part10=False)
    assert parsed.syntax.little is False and [a.code for a in parsed.anomalies] == ["no-part10-header"]


def test_bare_dataset_with_no_plausible_encoding_defaults_to_implicit():
    assert parse(b"\x08\x00\x10\x00" + b"\xff" * 20, part10=False).syntax.implicit is True


ELEMENTS = el(0x00080005, "CS", "ISO_IR 100") + el(0x00080016, "UI", "1.2") + el(0x00080060, "CS", "CT")
GARBAGE = b"\x10\x00\x10\x00zz\x00\x00"


@pytest.mark.parametrize("data,expected", [
    (b"\x08\x00\x60\x00CS\x00", False),  # 7 bytes
    (b"\x08\x00\x60\x00CS\x00\x00", True),  # one empty element, and the file ends cleanly after it
    (ELEMENTS + GARBAGE, True),  # three clean elements, garbage right after the third
    (el(0x00080005, "CS", "ISO_IR 100") + el(0x00080016, "UI", "1.2") + GARBAGE, False),  # only two
], ids=["7-bytes", "single-element", "three-then-garbage", "two-then-garbage"])
def test_dataset_detector_edges(data, expected):
    assert looks_like_dataset(data) is expected


# -- structure details ---------------------------------------------------------------------------

def test_item_elements_are_recorded_exactly():
    data = part10(seq(0x00081140, item(el(0x00100010, "PN", "X"))))
    [it] = [e for e in parse(data).elements if e.tag == ITEM]
    assert (it.vr, it.value_offset - it.offset, it.depth) == ("", 8, 1)


def test_ob_value_shaped_like_a_sequence_stays_ob():
    blob = item(el(0x00100010, "PN", "X", implicit=True))
    private = next(e for e in parse(part10(el(0x00091010, "OB", blob))).elements if e.tag == 0x00091010)
    assert private.vr == "OB"


def test_empty_item_in_an_unknown_value_is_a_sequence():
    private = next(e for e in parse(part10(el(0x00091010, "UN", item(b"")))).elements if e.tag == 0x00091010)
    assert (private.vr, private.vr_source) == ("SQ", "inferred")


def test_inferred_sequence_children_sit_one_level_down():
    data = part10(el(0x00091010, "UN", item(el(0x00100010, "PN", "HIDDEN", implicit=True))))
    child = next(e for e in parse(data).elements if e.tag == 0x00100010)
    assert child.depth == 1


def test_failed_inference_leaves_no_stray_items():
    junk = struct.pack("<HHI", 0xFFFE, 0xE000, 4) + b"\xff\xff\x00\x00"
    assert not any(e.tag == ITEM for e in parse(part10(el(0x00091010, "UN", junk))).elements)


def test_offset_table_length_problem_is_named():
    bad = part10(el(PIXEL_DATA, "OB", item(bytes(6)) + item(b"ab") + seq_delim(), length=UNDEF), ts=JPEG_BASELINE)
    assert "not a multiple of 4" in next(a.message for a in parse(bad).anomalies if a.code == "bad-offset-table")
    good = part10(encapsulated(b"ab", b"cd", bot=struct.pack("<2I", 0, 10)), ts=JPEG_BASELINE)
    assert "bad-offset-table" not in codes(good)


def test_group_length_anomaly_names_its_group():
    data = part10(el(0x00080000, "UL", struct.pack("<I", 99)) + el(0x00080060, "CS", "CT"))
    [anomaly] = [a for a in parse(data).anomalies if a.code == "group-length-mismatch"]
    assert anomaly.tag == 0x00080000


def test_long_vr_header_needs_twelve_bytes():
    data = part10() + tag(0x00091010) + b"OB\x00\x00\x01\x00"  # 10 of the 12 header bytes
    [anomaly] = [a for a in parse(data).anomalies if a.code == "truncated-header"]
    assert "OB header" in anomaly.message and anomaly.offset == len(data) - 10


# -- plausibility, the basis of transfer-syntax sniffing --------------------------------------------

def plausible(data: bytes, implicit: bool, little: bool = True) -> bool:
    return _Parser(data, Limits(), "file", [], [], _Tally())._plausible(0, implicit, little)


def test_plausibility_exact_fit_for_each_header_form():
    implicit = tag(0x00080016) + struct.pack("<I", 4) + b"1.2\x00"
    assert plausible(implicit, True) and not plausible(implicit[:-1], True)
    short = el(0x00080060, "CS", "CT")
    assert plausible(short, False) and not plausible(short[:-1], False)
    long = el(0x00091010, "OB", b"abcd")
    assert plausible(long, False) and not plausible(long[:-1], False)
    assert plausible(el(0x00091010, "OB", b"", length=UNDEF), False)
    assert not plausible(long[:11], False)  # 11 of the 12 header bytes


def test_plausibility_needs_eight_bytes_and_a_dataset_group():
    assert not plausible(tag(0x00080016) + b"\x00\x00\x00", True)
    assert plausible(tag(0x00080016) + struct.pack("<I", 0), True)
    for group, ok in ((0x0003, False), (0x0004, True), (0xFFFD, True), (0xFFFE, False)):
        assert plausible(struct.pack("<HHI", group, 0x0010, 0), True) is ok, hex(group)


def test_explicit_vr_sequence_is_parsed_after_sniffing():
    assert codes(part10(seq(0x00081140, item(el(0x00100010, "PN", "X"))), ts=EXPLICIT_LE)) == []
