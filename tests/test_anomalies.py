"""Every anomaly the parser can report, triggered on purpose.

One crafted input per anomaly code, and a completeness test: if a new code
is added to the parser without a case here, the build fails.
"""

import struct

import pytest

from builder import (
    DEFLATED_LE, EXPLICIT_LE, JPEG_BASELINE, PIXEL_DATA, UNDEF, deflate, el, image, item, part10, seq,
    seq_delim, tag, us,
)
from radguard.checks.structure import RULES
from radguard.dicom import Limits, parse


def raw_meta_without_ts() -> bytes:
    return bytes(128) + b"DICM" + el(0x00020001, "OB", b"\x00\x01")


def nested(levels: int) -> bytes:
    payload = el(0x00100010, "PN", "X")
    for _ in range(levels):
        payload = seq(0x00081140, item(payload, undefined=True), undefined=True)
    return payload


ITEM_START = struct.pack("<HHI", 0xFFFE, 0xE000, UNDEF)
ITEM_END_LEN4 = struct.pack("<HHI", 0xFFFE, 0xE00D, 4)

# (anomaly code, file bytes, parse keyword arguments)
CASES = [
    ("invalid-vr", part10(el(0x00100010, "PN", "A")) + b"\x10\x00\x20\x00zz\x04\x00ABCD", {}),
    ("length-overflow", part10(el(0x00091010, "OB", b"tiny", length=10_000)), {}),
    ("truncated-header", part10() + b"\x10\x00\x10", {}),
    ("odd-length", part10(el(0x00100010, "LO", b"abc")), {}),
    ("duplicate-tag", part10(el(0x00100010, "PN", "A") + el(0x00100010, "PN", "B")), {}),
    ("tag-order", part10(el(0x00100020, "LO", "ID") + el(0x00100010, "PN", "A")), {}),
    ("meta-group-length-mismatch", part10(image(4, 4), group_length_value=10), {}),
    ("missing-meta-group-length", part10(group_length=False), {}),
    ("group-length-mismatch",
     part10(el(0x00080000, "UL", struct.pack("<I", 99)) + el(0x00080060, "CS", "CT")), {}),
    ("transfer-syntax-mismatch", part10(image(4, 4, implicit=True), ts=EXPLICIT_LE), {}),
    ("missing-transfer-syntax", raw_meta_without_ts(), {}),
    ("unknown-transfer-syntax", part10(ts="1.2.3.4"), {}),
    ("reserved-nonzero", part10(tag(0x00091010) + b"OB\x01\x00" + struct.pack("<I", 2) + b"ab"), {}),
    ("vr-mismatch", part10(el(0x00280010, "UL", struct.pack("<I", 8))), {}),
    ("vr-length-mismatch", part10(el(0x00091010, "UL", bytes(6))), {}),
    ("stray-delimiter", part10(struct.pack("<HHI", 0xFFFE, 0xE00D, 0)), {}),
    ("bad-sequence-item", part10(el(0x00081140, "SQ", el(0x00100010, "PN", "X") + seq_delim(), length=UNDEF)), {}),
    ("missing-item-delimiter", part10(el(0x00081140, "SQ", ITEM_START + el(0x00100010, "PN", "X") + seq_delim(),
                                         length=UNDEF)), {}),
    ("missing-sequence-delimiter", part10(el(0x00081140, "SQ", item(el(0x00100010, "PN", "X")), length=UNDEF)), {}),
    ("unexpected-delimiter", part10(el(0x00081140, "SQ", seq_delim())), {}),
    ("delimiter-length", part10(el(0x00081140, "SQ", ITEM_START + ITEM_END_LEN4 + seq_delim(), length=UNDEF)), {}),
    ("undefined-length-invalid", part10(el(0x00100010, "OB", bytes(8), length=UNDEF)), {}),
    ("max-depth", part10(nested(40)), {}),
    ("element-limit", part10(b"".join(el(0x00091000 + i, "OB", b"") for i in range(1, 40))),
     {"limits": Limits(max_elements=10)}),
    ("deflate-bomb", part10(deflate(el(0x00091010, "OB", bytes(1 << 16))), ts=DEFLATED_LE),
     {"limits": Limits(max_inflated=1024)}),
    ("deflate-truncated", part10(deflate(image(8, 8))[:-8], ts=DEFLATED_LE), {}),
    ("deflate-error", part10(b"\xff" * 32, ts=DEFLATED_LE), {}),
    ("unterminated-pixel-data", part10(el(PIXEL_DATA, "OB", item(b"") + item(b"ab"), length=UNDEF),
                                       ts=JPEG_BASELINE), {}),
    ("bad-fragment-item", part10(el(PIXEL_DATA, "OB", item(b"") + el(0x00100010, "PN", "X"), length=UNDEF),
                                 ts=JPEG_BASELINE), {}),
    ("undefined-fragment-length", part10(el(PIXEL_DATA, "OB", item(b"") + ITEM_START + bytes(8), length=UNDEF),
                                         ts=JPEG_BASELINE), {}),
    ("bad-offset-table", part10(el(PIXEL_DATA, "OB", item(bytes(6)) + item(b"ab") + seq_delim(), length=UNDEF),
                                ts=JPEG_BASELINE), {}),
    ("no-part10-header", image(4, 4), {"part10": False}),
    ("suppressed", part10(b"".join(el(0x00091000 + i, "OB", b"x") for i in range(1, 120))), {}),
]


@pytest.mark.parametrize("code,data,kwargs", CASES, ids=[c[0] for c in CASES])
def test_anomaly_is_reported(code, data, kwargs):
    codes = [a.code for a in parse(data, **kwargs).anomalies]
    assert code in codes


def test_every_rule_has_a_triggering_case():
    assert {code for code, _, _ in CASES} == set(RULES)


def test_odd_fragment_length_is_reported():
    data = part10(el(PIXEL_DATA, "OB", item(b"") + item(b"abc") + seq_delim(), length=UNDEF), ts=JPEG_BASELINE)
    assert "odd-length" in [a.code for a in parse(data).anomalies]


def test_unknown_vr_value_with_undefined_length_is_inferred_as_sequence():
    # Implicit VR, private tag unknown to the dictionary, undefined length: only a sequence can be that.
    content = item(el(0x00100010, "PN", "X", implicit=True), undefined=True)
    data = part10(el(0x00091010, "UN", content + seq_delim(), implicit=True, length=UNDEF),
                  ts="1.2.840.10008.1.2")
    private = next(e for e in parse(data).elements if e.tag == 0x00091010)
    assert (private.vr, private.vr_source) == ("SQ", "inferred")


def test_valid_offset_table_is_recorded_for_framing():
    frag = item(bytes(4))
    data = part10(el(PIXEL_DATA, "OB", item(struct.pack("<2I", 0, len(frag))) + frag + frag + seq_delim(),
                     length=UNDEF), ts=JPEG_BASELINE)
    px = next(e for e in parse(data).elements if e.tag == PIXEL_DATA)
    assert px.offset_table == [0, len(frag)]


def test_limits_reject_nonsense():
    with pytest.raises(ValueError):
        Limits(max_elements=0)


def test_us_helper_round_trips():  # guards the builder the cases above depend on
    assert us(0x00280010, 7)[-2:] == b"\x07\x00"
