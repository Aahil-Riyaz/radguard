"""Codestream walkers: find where a compressed frame really ends."""

import struct

import pytest

from builder import j2k, jpeg, rle_frame
from radguard.codecs import j2k_end, jpeg_end, rle_problem


def test_jpeg_end_is_the_byte_after_eoi():
    data = jpeg()
    assert jpeg_end(data) == (len(data), None)


def test_jpeg_thumbnail_eoi_inside_app1_is_not_the_end():
    # EXIF thumbnails carry a complete JPEG, EOI included, inside APP1.
    data = jpeg(app1=b"Exif\x00\x00" + jpeg())
    assert jpeg_end(data) == (len(data), None)


def test_jpeg_entropy_data_stuffing_restarts_and_fill():
    data = jpeg(entropy=b"\x01\xff\x00\x02\xff\xd3\x03\xff\xff\xff")  # stuffed FF, RST3, fill before EOI
    assert jpeg_end(data) == (len(data), None)


def test_jpeg_trailing_bytes_are_excluded():
    data = jpeg()
    assert jpeg_end(data + b"HIDDEN")[0] == len(data)


@pytest.mark.parametrize("data,problem", [
    (b"\x89PNG\r\n\x1a\n", "does not start with SOI"),
    (jpeg()[:-2], "no EOI"),
    (b"\xff\xd8\xff\xe0\x00\x01", "invalid length 1"),
    (b"\xff\xd8\xff\xe0\x10\x00abc", "runs past the end"),
    (b"\xff\xd8\xff\xd8", "second SOI"),
    (b"\xff\xd8\x00", "expected a marker"),
])
def test_jpeg_problems(data, problem):
    end, found = jpeg_end(data)
    assert end is None and problem in found


def test_jpeg_ls_uses_its_own_marker_rule():
    # In JPEG-LS, FF followed by a byte below 0x80 is data; in JPEG it would be a marker.
    data = jpeg(entropy=b"\x01\xff\x7f\x02")
    assert jpeg_end(data, ls=True) == (len(data), None)
    assert jpeg_end(data)[0] is None


def test_j2k_end_follows_tile_part_lengths():
    data = j2k()
    assert j2k_end(data) == (len(data), None)


def test_j2k_last_tile_part_without_length():
    data = j2k(psot_zero=True)
    assert j2k_end(data) == (len(data), None)


def test_j2k_ff_d9_inside_a_header_comment_is_not_the_end():
    data = j2k(comment=b"\x00\x01note\xff\xd9tail")
    assert j2k_end(data) == (len(data), None)
    assert j2k_end(data + b"HIDDEN")[0] == len(data)


@pytest.mark.parametrize("mutate,problem", [
    (lambda d: b"\xff\xd8" + d[2:], "does not start with SOC"),
    (lambda d: d[:-2], "expected EOC"),
    (lambda d: d[:20], "runs past the end"),
])
def test_j2k_problems(mutate, problem):
    end, found = j2k_end(mutate(j2k()))
    assert end is None and problem in found


def test_j2k_invalid_tile_part_length():
    data = bytearray(j2k())
    sot = data.index(b"\xff\x90")
    struct.pack_into(">I", data, sot + 6, 5)
    assert "invalid length 5" in j2k_end(bytes(data))[1]


def test_rle_header():
    assert rle_problem(rle_frame(3)) is None
    assert "segment count 0" in rle_problem(struct.pack("<16I", 0, *[0] * 15))
    assert "not increasing" in rle_problem(struct.pack("<16I", 2, 64, 64, *[0] * 13) + bytes(8))
    assert "shorter" in rle_problem(b"\x01")


def test_jpeg_ff00_outside_entropy_data_is_not_a_marker():
    end, problem = jpeg_end(b"\xff\xd8\xff\x00\x00\x04ab\xff\xd9")
    assert end is None and "not a marker" in problem


def test_jpeg_standalone_markers_before_the_scan_are_skipped():
    data = b"\xff\xd8\xff\x01\xff\xd0" + jpeg()[2:]  # TEM and RST0 have no length field
    assert jpeg_end(data) == (len(data), None)


@pytest.mark.parametrize("walker,data", [
    (jpeg_end, b"\xff\xd8" + b"\xff\xfe\x00\x02" * 10 + b"\xff\xd9"),  # ten empty COM segments
    (j2k_end, j2k(comment=b"\x00\x01x")),
])
def test_walkers_stop_at_the_segment_cap(monkeypatch, walker, data):
    monkeypatch.setattr("radguard.codecs.MAX_SEGMENTS", 3)
    end, problem = walker(data)
    assert end is None and "more than 3" in problem


def test_rle_unused_offsets_must_be_zero():
    frame = struct.pack("<16I", 1, 64, 99, *[0] * 13) + bytes(4)
    assert "unused segment offsets" in rle_problem(frame)
