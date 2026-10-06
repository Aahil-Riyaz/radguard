"""Codestream check: reassembled frames, their true ends, and what hides after them."""

from builder import JPEG_BASELINE, el, encapsulated, even, fake_pe, image, j2k, jpeg, part10, rle_frame
from conftest import findings_for
from radguard.findings import Severity

J2K_LOSSLESS = "1.2.840.10008.1.2.4.90"
RLE = "1.2.840.10008.1.2.5"


def compressed(*fragments, ts=JPEG_BASELINE, frames=None):
    return part10(image(8, 8, frames=frames, pixel_element=encapsulated(*map(even, fragments))), ts=ts)


def by_check(data):
    return {f.check: f for f in findings_for(data, "pixels.")}


def test_clean_frames_have_no_findings():
    assert by_check(compressed(jpeg())) == {}
    assert by_check(compressed(j2k(), ts=J2K_LOSSLESS)) == {}
    assert by_check(compressed(rle_frame(), ts=RLE)) == {}


def test_frame_split_across_fragments_is_reassembled():
    data = jpeg()
    assert by_check(compressed(data[:40], data[40:])) == {}


def test_second_image_hidden_after_end_of_frame():
    finding = by_check(compressed(jpeg() + jpeg()))["pixels.codestream-trailing-data"]
    assert finding.severity is Severity.HIGH
    assert finding.title == "Second image hidden after the end of a frame"


def test_second_image_in_its_own_fragment_of_a_single_frame_file():
    # One declared frame: decoders concatenate every fragment and stop at the first EOI.
    finding = by_check(compressed(jpeg(), jpeg()))["pixels.codestream-trailing-data"]
    assert "second image" in finding.detail


def test_executable_after_end_of_frame_is_critical():
    finding = by_check(compressed(jpeg() + fake_pe()))["pixels.codestream-trailing-data"]
    assert finding.severity is Severity.CRITICAL
    assert "Windows PE executable" in finding.detail


def test_trailing_data_after_j2k_codestream():
    assert "pixels.codestream-trailing-data" in by_check(compressed(j2k() + bytes(range(100)), ts=J2K_LOSSLESS))


def test_frame_that_is_not_the_declared_codec():
    finding = by_check(compressed(fake_pe()))["pixels.codec-mismatch"]
    assert finding.severity is Severity.CRITICAL


def test_malformed_codestream():
    assert by_check(compressed(jpeg()[:-2] + b"\x00\x00"))["pixels.malformed-codestream"].severity is Severity.MEDIUM
    assert "pixels.malformed-codestream" in by_check(compressed(b"\x00" * 70, ts=RLE))


def test_undeclared_frames():
    data = compressed(jpeg(), jpeg(), jpeg(), frames=2)
    assert by_check(data)["pixels.hidden-frames"].title == "1 undeclared frame(s)"


def test_value_scan_does_not_double_report_fragments():
    data = compressed(jpeg() + fake_pe())
    assert not [f for f in findings_for(data, "values.")]


def test_padding_byte_after_eoi_is_legal():
    assert by_check(compressed(jpeg() + b"\x00")) == {}
    assert "pixels.codestream-trailing-data" in by_check(compressed(jpeg() + b"\x01\x00"))


def test_unrelated_transfer_syntax_is_ignored():
    assert by_check(part10(image(8, 8) + el(0x00091010, "OB", jpeg()))) == {}
