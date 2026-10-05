"""The parser: every encoding, every structure, and exact byte accounting."""

import struct

import pytest

from builder import (
    DEFLATED_LE, EXPLICIT_BE, EXPLICIT_LE, IMPLICIT_LE, JPEG_BASELINE, PIXEL_DATA, UNDEF,
    deflate, el, encapsulated, image, item, meta, part10, seq, us,
)
from radguard.dicom import Limits, coverage, parse, values
from radguard.dicom.model import ITEM


def codes(parsed):
    return [a.code for a in parsed.anomalies]


def tags(parsed, domain="file"):
    return [el.tag for el in parsed.elements if el.domain == domain and el.tag != ITEM]


def assert_fully_explained(parsed):
    assert coverage.gaps(parsed.regions, parsed.size) == []


@pytest.mark.parametrize("ts,implicit,little", [
    (EXPLICIT_LE, False, True),
    (IMPLICIT_LE, True, True),
    (EXPLICIT_BE, False, False),
])
def test_every_native_encoding_parses_cleanly(ts, implicit, little):
    data = part10(image(4, 4, implicit=implicit, little=little), ts=ts)
    parsed = parse(data)
    assert codes(parsed) == []
    assert_fully_explained(parsed)
    assert PIXEL_DATA in tags(parsed)
    rows = next(e for e in parsed.elements if e.tag == 0x00280010)
    assert rows.vr == "US"
    assert rows.vr_source == ("dictionary" if implicit else "explicit")
    assert values.number(data, rows) == 4


def test_offsets_are_exact():
    dataset = el(0x00100010, "PN", "DOE^JANE")
    data = part10(dataset)
    parsed = parse(data)
    name = next(e for e in parsed.elements if e.tag == 0x00100010)
    assert name.offset == len(data) - len(dataset)
    assert name.value_offset == name.offset + 8
    assert data[name.value_offset : name.end] == b"DOE^JANE"


@pytest.mark.parametrize("seq_undefined", [False, True])
@pytest.mark.parametrize("item_undefined", [False, True])
def test_nested_sequences(seq_undefined, item_undefined):
    inner = seq(0x00081150, item(el(0x00081155, "UI", "1.2.3"), undefined=item_undefined),
                undefined=seq_undefined)
    outer = seq(0x00081140, item(inner, undefined=item_undefined), item(b"", undefined=item_undefined),
                undefined=seq_undefined)
    parsed = parse(part10(outer + el(0x00100010, "PN", "X")))
    assert codes(parsed) == []
    assert_fully_explained(parsed)
    leaf = next(e for e in parsed.elements if e.tag == 0x00081155)
    assert leaf.depth == 2
    assert sum(e.tag == ITEM for e in parsed.elements) == 3
    assert parsed.elements[-1].tag == 0x00100010 and parsed.elements[-1].depth == 0


def test_un_with_undefined_length_is_parsed_as_implicit_sequence():
    # PS3.5 6.2.2: a UN of undefined length holds an implicit VR LE sequence.
    content = item(el(0x00100010, "PN", "X", implicit=True), undefined=True)
    data = part10(seq(0x00091010, content, undefined=True, vr="UN"))
    parsed = parse(data)
    assert codes(parsed) == []
    assert_fully_explained(parsed)
    assert 0x00100010 in tags(parsed)


def test_defined_length_value_that_is_secretly_a_sequence_is_inferred():
    content = item(el(0x00100010, "PN", "HIDDEN", implicit=True))
    parsed = parse(part10(el(0x00091010, "UN", content)))
    private = next(e for e in parsed.elements if e.tag == 0x00091010)
    assert private.vr == "SQ" and private.vr_source == "inferred"
    assert 0x00100010 in tags(parsed)
    assert_fully_explained(parsed)


def test_failed_sequence_inference_rolls_back_cleanly():
    # Starts like an Item but is garbage: must stay an opaque value with no anomalies.
    junk = struct.pack("<HHI", 0xFFFE, 0xE000, 4) + b"\xff\xff\x00\x00"
    parsed = parse(part10(el(0x00091010, "UN", junk)))
    private = next(e for e in parsed.elements if e.tag == 0x00091010)
    assert private.vr == "UN"
    assert codes(parsed) == []
    assert_fully_explained(parsed)


def test_encapsulated_pixel_data_and_offset_table():
    frags = (b"\xff\xd8" + bytes(10), b"\xff\xd8" + bytes(6))
    bot = struct.pack("<2I", 0, 8 + len(frags[0]))
    data = part10(image(4, 4, pixel_element=encapsulated(*frags, bot=bot)), ts=JPEG_BASELINE)
    parsed = parse(data)
    px = next(e for e in parsed.elements if e.tag == PIXEL_DATA)
    assert [n for _, n in px.fragments] == [12, 8]
    assert codes(parsed) == []
    assert_fully_explained(parsed)


def test_bad_offset_table_is_reported():
    data = part10(encapsulated(bytes(12), bot=struct.pack("<I", 999)), ts=JPEG_BASELINE)
    assert "bad-offset-table" in codes(parse(data))


def test_deflated_dataset_is_parsed_in_its_own_domain():
    dataset = image(4, 4)
    parsed = parse(part10(deflate(dataset), ts=DEFLATED_LE))
    assert parsed.inflated == dataset
    assert PIXEL_DATA in tags(parsed, "inflated")
    assert codes(parsed) == []
    assert_fully_explained(parsed)


def test_bytes_after_the_deflate_stream_are_unexplained():
    stream = deflate(image(4, 4))
    data = part10(stream, ts=DEFLATED_LE) + b"SECRET"
    assert coverage.gaps(parse(data).regions, len(data)) == [(len(data) - 6, len(data))]


def test_decompression_bomb_is_bounded():
    data = part10(deflate(el(0x00091010, "OB", bytes(1 << 20))), ts=DEFLATED_LE)
    parsed = parse(data, Limits(max_inflated=64 << 10))
    assert "deflate-bomb" in codes(parsed)
    assert len(parsed.inflated) <= 64 << 10


def test_transfer_syntax_mismatch_is_detected_and_survived():
    parsed = parse(part10(image(4, 4, implicit=True), ts=EXPLICIT_LE))
    assert codes(parsed) == ["transfer-syntax-mismatch"]
    assert PIXEL_DATA in tags(parsed)
    assert_fully_explained(parsed)


def test_meta_group_length_lie():
    honest = len(meta(group_length=False))
    parsed = parse(part10(image(4, 4), group_length_value=honest - 30))
    assert "meta-group-length-mismatch" in codes(parsed)


def test_missing_meta_group_length():
    assert "missing-meta-group-length" in codes(parse(part10(group_length=False)))


def test_ordering_and_duplicates():
    data = part10(el(0x00100020, "LO", "ID") + el(0x00100010, "PN", "A") + el(0x00100010, "PN", "B"))
    assert codes(parse(data)) == ["tag-order", "duplicate-tag"]


def test_vr_mismatch_and_length_checks():
    data = part10(el(0x00280010, "UL", struct.pack("<I", 8)) + el(0x00280011, "US", b"\x08\x00\x00"))
    assert codes(parse(data)) == ["vr-mismatch", "vr-length-mismatch", "odd-length"]


def test_invalid_vr_stops_parsing_and_leaves_rest_unexplained():
    good = el(0x00100010, "PN", "A")
    data = part10(good) + b"\x10\x00\x20\x00zz\x04\x00ABCD"
    parsed = parse(data)
    assert codes(parsed) == ["invalid-vr"]
    assert coverage.gaps(parsed.regions, len(data)) == [(len(data) - 12, len(data))]


def test_length_overflow_does_not_claim_bytes_it_cannot_own():
    data = part10(el(0x00091010, "OB", b"tiny", length=10_000))
    parsed = parse(data)
    assert codes(parsed) == ["length-overflow"]
    assert coverage.gaps(parsed.regions, len(data)) == [(len(data) - 4, len(data))]


def test_defined_length_item_resynchronises_after_corruption():
    broken = item(b"\x10\x00\x10\x00zz\x02\x00AB")  # invalid VR inside a defined-length item
    data = part10(seq(0x00081140, broken) + el(0x00100010, "PN", "AFTER"))
    parsed = parse(data)
    assert codes(parsed) == ["invalid-vr"]
    assert parsed.elements[-1].tag == 0x00100010  # parsing resumed after the item


def test_deep_nesting_is_bounded():
    payload = el(0x00100010, "PN", "X")
    for _ in range(100):
        payload = seq(0x00081140, item(payload, undefined=True), undefined=True)
    parsed = parse(part10(payload))
    assert "max-depth" in codes(parsed)


def test_element_flood_is_bounded():
    flood = b"".join(el(0x00091000 + i, "OB", b"") for i in range(1, 200))
    parsed = parse(part10(flood), Limits(max_elements=50))
    assert "element-limit" in codes(parsed)
    assert len(parsed.elements) <= 50


def test_undefined_length_on_plain_attribute():
    data = part10(el(0x00100010, "OB", b"\x00" * 8, length=UNDEF))
    assert codes(parse(data)) == ["undefined-length-invalid"]


def test_unknown_and_missing_transfer_syntax():
    assert "unknown-transfer-syntax" in codes(parse(part10(ts="1.2.3.4.5")))
    no_ts = b"\x00" * 128 + b"DICM" + el(0x00020001, "OB", b"\x00\x01")
    assert "missing-transfer-syntax" in codes(parse(no_ts))


def test_sequence_inside_meta_cannot_confuse_dataset_start():
    # Implicit dataset whose first bytes are not a valid VR must not break meta parsing.
    data = part10(us(0x00280010, 4, implicit=True), ts=IMPLICIT_LE)
    parsed = parse(data)
    assert codes(parsed) == []
    assert_fully_explained(parsed)
