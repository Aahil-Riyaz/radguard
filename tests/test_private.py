"""Private data elements: reservation rules, opaque blobs, and payloads hidden by compression."""

import gzip
import random
import zlib

import pytest

from builder import DEFLATED_LE, deflate, el, fake_elf, fake_pe, image, item, part10, seq
from conftest import findings_for
from radguard.checks import private
from radguard.findings import Severity

RANDOM = random.Random(4).randbytes(8192)  # stands in for encrypted data


def creator(group: int, block: int, name: str) -> bytes:
    return el(group << 16 | block, "LO", name)


def data(group: int, block: int, offset: int, value: bytes, vr: str = "OB") -> bytes:
    return el(group << 16 | block << 8 | offset, vr, value + b"\x00" * (len(value) % 2))


def vendor(value: bytes, name: str = "ACME 1.0") -> bytes:
    return part10(creator(0x0029, 0x10, name) + data(0x0029, 0x10, 0x10, value))


def by_check(blob: bytes) -> dict:
    return {f.check: f for f in findings_for(blob, "private.")}


# -- reservation rules ----------------------------------------------------------------------

def test_well_formed_vendor_block_is_clean():
    assert by_check(vendor(b"vendor settings v2")) == {}


def test_orphan_private_data():
    finding = by_check(part10(data(0x0029, 0x10, 0x10, b"secret")))["private.orphan-element"]
    assert finding.severity is Severity.MEDIUM and "(0029,0010)" in finding.detail


def test_creator_must_be_in_the_same_dataset():
    # The creator is at the top level; the data sits inside a sequence item, a different dataset.
    blob = part10(seq(0x00081140, item(data(0x0029, 0x10, 0x10, b"x"))) + creator(0x0029, 0x10, "ACME"))
    assert "private.orphan-element" in by_check(blob)


@pytest.mark.parametrize("group", [0x0001, 0x0003, 0x0005, 0x0007])
def test_forbidden_private_groups(group):
    blob = part10(creator(group, 0x10, "ACME") + data(group, 0x10, 0x01, b"x"))
    assert "private.illegal-group" in by_check(blob)


@pytest.mark.parametrize("elem", [0x0005, 0x0100, 0x0500])
def test_elements_outside_any_block(elem):
    assert "private.unusable-element" in by_check(part10(el(0x0029 << 16 | elem, "OB", b"xx")))


@pytest.mark.parametrize("value,vr", [(b"", "LO"), (b"AC\x1bME", "LO"), (b"ACME", "SH")],
                         ids=["empty", "control-char", "wrong-vr"])
def test_malformed_creators(value, vr):
    assert "private.creator-invalid" in by_check(part10(el(0x00290010, vr, value)))


def test_creator_reserving_two_blocks():
    blob = part10(creator(0x0029, 0x10, "ACME") + creator(0x0029, 0x11, "ACME"))
    assert "private.duplicate-creator" in by_check(blob)


# -- opaque blobs -------------------------------------------------------------------------------

def test_high_entropy_blob_of_unknown_format():
    finding = by_check(vendor(RANDOM))["private.opaque-blob"]
    assert finding.severity is Severity.MEDIUM and "[ACME 1.0]" in finding.detail


@pytest.mark.parametrize("value", [b"\xff\xd8\xff\xe0" + RANDOM, bytes(8192), RANDOM[:2048]],
                         ids=["jpeg-explains-entropy", "low-entropy", "too-small"])
def test_explained_or_small_blobs_are_not_opaque(value):
    assert "private.opaque-blob" not in by_check(vendor(value))


def test_fake_compression_header_does_not_hide_an_opaque_blob():
    # Two bytes that look like a zlib header must not exempt random data from the entropy check.
    assert "private.opaque-blob" in by_check(vendor(b"\x78\x9c" + RANDOM))


# -- compressed payloads ------------------------------------------------------------------------

@pytest.mark.parametrize("compress", [zlib.compress, gzip.compress], ids=["zlib", "gzip"])
def test_executable_hidden_by_compression_is_found(compress):
    payload = compress(b"harmless-looking vendor header\n" * 20 + fake_pe(512))
    assert b"MZ" not in payload  # invisible to any signature search of the file itself
    finding = by_check(vendor(payload))["private.compressed-payload"]
    assert finding.severity is Severity.CRITICAL and "decompressed offset" in finding.detail


def test_benign_compressed_vendor_data_is_clean():
    assert by_check(vendor(zlib.compress(b"<settings gain='2'/>" * 500))) == {}


def test_data_after_the_compressed_stream():
    finding = by_check(vendor(zlib.compress(b"tiny") + RANDOM))["private.data-after-stream"]
    assert "follow the end of the compressed stream" in finding.detail


def test_decompression_bomb_is_bounded(monkeypatch):
    monkeypatch.setattr(private, "INFLATE_PER_VALUE", 1 << 20)
    finding = by_check(vendor(zlib.compress(bytes(8 << 20))))["private.decompression-bomb"]
    assert finding.severity is Severity.HIGH


def test_exhausted_file_budget_never_means_unlimited(monkeypatch):
    # Regression: zlib reads max_length=0 as "no limit". Once the budget reaches zero,
    # further blobs must be reported, not inflated without a cap.
    first = zlib.compress(bytes(4096))
    monkeypatch.setattr(private, "INFLATE_PER_FILE", 4096)
    blob = part10(creator(0x0029, 0x10, "ACME") + data(0x0029, 0x10, 0x10, first)
                  + data(0x0029, 0x10, 0x11, zlib.compress(bytes(50 << 20))))
    finding = by_check(blob)["private.decompression-bomb"]
    assert "budget is spent" in finding.detail


def test_signature_flood_inside_compressed_data_is_reported():
    assert "private.analysis-incomplete" in by_check(vendor(zlib.compress(b"MZ" * 40_000)))


def test_private_data_inside_a_deflated_dataset():
    dataset = creator(0x0029, 0x10, "ACME") + data(0x0029, 0x10, 0x10, zlib.compress(fake_elf()))
    found = by_check(part10(deflate(image(4, 4, extra=dataset)), ts=DEFLATED_LE))  # group 0029 sorts before 7FE0
    assert "private.compressed-payload" in found
