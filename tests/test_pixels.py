"""Pixel check: the image header is a contract; breaking it hides data or breaks decoders."""

from builder import JPEG_BASELINE, PIXEL_DATA, el, encapsulated, fake_pe, image, part10, us
from conftest import findings_for
from radguard.findings import Severity


def by_check(data):
    return {f.check: f for f in findings_for(data, "pixels.")}


def test_consistent_image_is_clean():
    assert by_check(part10(image(8, 8))) == {}
    assert by_check(part10(image(3, 3))) == {}  # 9 bytes + 1 legal pad byte
    assert by_check(part10(image(4, 4, bits=16))) == {}


def test_duplicate_pixel_data_is_critical():
    found = by_check(part10(image(8, 8) + el(PIXEL_DATA, "OB", bytes(64))))
    assert found["pixels.duplicate-pixel-data"].severity is Severity.CRITICAL


def test_small_slack_is_medium():
    finding = by_check(part10(image(8, 8, bytes(64) + b"hi")))["pixels.slack"]
    assert finding.severity is Severity.MEDIUM
    assert "2 bytes hidden" in finding.title


def test_slack_holding_whole_frames_is_reported_as_hidden_frames():
    finding = by_check(part10(image(8, 8, bytes(64) + bytes([200]) * 128)))["pixels.slack"]
    assert finding.severity is Severity.HIGH
    assert finding.title.startswith("2 hidden frame(s)")


def test_executable_in_slack_is_critical():
    finding = by_check(part10(image(8, 8, bytes(64) + fake_pe())))["pixels.slack"]
    assert finding.severity is Severity.CRITICAL
    assert "Windows PE executable" in finding.detail


def test_executable_stored_as_image_pixels():
    finding = by_check(part10(image(16, 16, fake_pe(256))))["pixels.embedded-file"]
    assert finding.severity is Severity.CRITICAL
    assert "stored as image pixels" in finding.title


def test_truncated_pixel_data():
    assert by_check(part10(image(8, 8, bytes(40))))["pixels.truncated"].severity is Severity.HIGH


def test_size_overflowing_32_bits():
    data = part10(image(65535, 65535, bytes(16), bits=16))
    finding = by_check(data)["pixels.size-overflow"]
    assert "heap overflow" in finding.detail


def test_frames_count_in_geometry():
    assert by_check(part10(image(4, 4, bytes(48), frames=3))) == {}
    assert "pixels.truncated" in by_check(part10(image(4, 4, bytes(32), frames=3)))


def test_zero_or_negative_geometry():
    assert "pixels.invalid-geometry" in by_check(part10(image(4, 4, bytes(16), frames=-5)))
    assert "pixels.invalid-geometry" in by_check(part10(image(0, 4, bytes(16))))


def test_encoding_mismatch_both_ways():
    native_in_jpeg = part10(image(4, 4), ts=JPEG_BASELINE)
    assert "pixels.encoding-mismatch" in by_check(native_in_jpeg)
    fragments_in_native = part10(image(4, 4, pixel_element=encapsulated(bytes(8))))
    assert "pixels.encoding-mismatch" in by_check(fragments_in_native)


def test_conflicting_geometry_is_ambiguous():
    data = part10(image(8, 8, extra=us(0x00280010, 16)))  # a second Rows, after the first
    finding = by_check(data)["pixels.ambiguous-geometry"]
    assert finding.severity is Severity.HIGH and "(8, 16)" in finding.detail


def test_repeated_but_identical_geometry_is_not_ambiguous():
    assert "pixels.ambiguous-geometry" not in by_check(part10(image(8, 8, extra=us(0x00280010, 8))))
