"""Private-data and creator-name edges, written against surviving mutants."""

import random
import zlib

import pytest

from builder import el, fake_pe, image, part10
from conftest import findings_for
from radguard.checks import private
from radguard.dicom import parse, paths
from radguard.findings import Severity

RANDOM = random.Random(11).randbytes(8192)


def creator(group: int, block: int, name: str) -> bytes:
    return el(group << 16 | block, "LO", name)


def data(group: int, elem: int, value: bytes, vr: str = "OB") -> bytes:
    return el(group << 16 | elem, vr, value + b"\x00" * (len(value) % 2))


def by_check(blob: bytes) -> dict:
    return {f.check: f for f in findings_for(blob, "private.")}


def vendor(value: bytes, vr: str = "OB") -> bytes:
    return part10(creator(0x0029, 0x10, "ACME 1.0") + data(0x0029, 0x1010, value, vr))


# -- reservation ranges -----------------------------------------------------------------------------

def test_group_ffff_is_forbidden():
    assert "private.illegal-group" in by_check(part10(el(0xFFFF0010, "LO", "ACME") + data(0xFFFF, 0x1001, b"x")))


def test_last_creator_block_and_first_data_element():
    blob = part10(creator(0x0029, 0x10, "A") + creator(0x0029, 0xFF, "Z")
                  + data(0x0029, 0x1000, b"first") + data(0x0029, 0xFF01, b"last"))
    assert by_check(blob) == {}


@pytest.mark.parametrize("name,ok", [("C" * 64, True), ("C" * 65, False), ("AC\x7fME", False)],
                         ids=["64-chars", "65-chars", "DEL"])
def test_creator_length_and_characters(name, ok):
    assert ("private.creator-invalid" not in by_check(part10(el(0x00290010, "LO", name.encode())))) is ok


# -- opaque blobs -------------------------------------------------------------------------------------

def test_opaque_size_threshold():
    assert "private.opaque-blob" not in by_check(vendor(RANDOM[:4094]))
    assert "private.opaque-blob" in by_check(vendor(RANDOM[:4096]))


def test_entropy_threshold_is_inclusive():
    # 64 symbols at 1/128 and 128 symbols at 1/256: exactly 7.5 bits per byte.
    value = bytes(range(0x40, 0x80)) * 32 + bytes(range(0x80, 0x100)) * 16
    assert "private.opaque-blob" in by_check(vendor(value))


def test_only_binary_values_are_judged_as_blobs():
    assert "private.opaque-blob" not in by_check(vendor(RANDOM, vr="UT"))


# -- decompression --------------------------------------------------------------------------------------

def test_ratio_limit_is_named():
    finding = by_check(vendor(zlib.compress(bytes(8 << 20))))["private.decompression-bomb"]
    assert "expands more than 1000:1" in finding.detail


def test_per_value_limit_is_named(monkeypatch):
    monkeypatch.setattr(private, "INFLATE_PER_VALUE", 1 << 20)
    finding = by_check(vendor(zlib.compress(bytes(8 << 20))))["private.decompression-bomb"]
    assert "expands beyond 1,048,576 bytes" in finding.detail


def test_truncated_compressed_data_is_not_a_bomb():
    assert "private.decompression-bomb" not in by_check(vendor(zlib.compress(RANDOM)[:5000]))


@pytest.mark.parametrize("n,reported", [(15, False), (16, True)])
def test_data_after_stream_threshold(n, reported):
    # Written without the even-length pad byte, so exactly n bytes follow the stream.
    value = zlib.compress(b"tiny") + bytes(range(1, n + 1))
    found = by_check(part10(creator(0x0029, 0x10, "ACME") + el(0x00291010, "OB", value)))
    assert ("private.data-after-stream" in found) is reported


def test_compressed_payload_finding_points_at_the_value():
    blob = vendor(zlib.compress(fake_pe(512)))
    finding = by_check(blob)["private.compressed-payload"]
    value = next(e for e in parse(blob).elements if e.tag == 0x00291010)
    assert finding.offset == value.value_offset and finding.severity is Severity.CRITICAL


# -- creator names in locations ---------------------------------------------------------------------------

def test_private_creators_are_collected_per_block():
    blob = part10(creator(0x0029, 0x10, "ACME") + creator(0x0029, 0xFF, "LAST")
                  + el(0x00290100, "OB", b"xx") + image(2, 2))
    found = paths.private_creators(parse(blob), blob)
    assert found == {("file", None, 0x0029, 0x10): "ACME", ("file", None, 0x0029, 0xFF): "LAST"}


@pytest.mark.parametrize("tag,name", [
    (0x00291010, "Private [ACME]"), (0x0029FF01, "Private [LAST]"), (0x00291110, "Private [no creator]"),
    (0x00290FFF, "Private"), (0x00291000, "Private [ACME]"), (0x00281050, "WindowCenter"),
])
def test_names_include_the_owning_creator(tag, name):
    blob = part10(creator(0x0029, 0x10, "ACME") + creator(0x0029, 0xFF, "LAST") + el(tag, "OB", b"xx"))
    parsed = parse(blob)
    target = next(e for e in parsed.elements if e.tag == tag)
    assert paths.name(target, paths.private_creators(parsed, blob)) == name


def test_creator_names_are_reduced_to_printable_ascii():
    blob = part10(el(0x00290010, "LO", b"AC\x01\x7fME~"))
    assert paths.private_creators(parse(blob), blob)[("file", None, 0x0029, 0x10)] == "AC..ME~"


def test_executable_in_a_private_value_is_reported_with_its_creator():
    finding = next(f for f in findings_for(vendor(fake_pe(128))) if f.check == "values.embedded-file")
    assert "(0029,1010) Private [ACME 1.0]" in finding.detail


def test_executable_in_trailing_padding_is_reported_once():
    blob = part10(image(4, 4) + el(0xFFFCFFFC, "OB", fake_pe(128)))
    found = {f.check for f in findings_for(blob)}
    assert "structure.nonzero-padding" in found and "values.embedded-file" not in found


def test_locator_first_leaf_and_value_end():
    blob = part10(el(0x00291010, "OB", fake_pe(96)) + el(0x00291011, "OB", b"xy"))
    parsed = parse(blob)
    loc = paths.Locator(parsed, "file", blob)
    first_leaf = parsed.elements[0]  # (0002,0000): the very first value span
    assert loc.element_at(first_leaf.value_offset) is first_leaf
    a, b = (next(e for e in parsed.elements if e.tag == t) for t in (0x00291010, 0x00291011))
    assert loc.element_at(a.end) is not a  # one past the value belongs to the next header
    assert loc.element_at(b.end) is None
