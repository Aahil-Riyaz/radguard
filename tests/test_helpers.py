"""Small helpers that findings and the map view depend on: names, value rendering, output."""

import os
import struct

import pytest

from builder import DEFLATED_LE, JPEG_BASELINE, deflate, el, encapsulated, image, item, part10, seq
from radguard.cli import main
from radguard.dicom import dictionary, parse, values
from radguard.mapview import render


@pytest.mark.parametrize("tag,name", [
    (0x00280010, "Rows"),
    (0x00090000, "PrivateGroupLength"),
    (0x00090010, "PrivateCreator"),
    (0x00091010, "Private"),
    (0x00080000, "GroupLength"),
    (0xFFFEE000, "Item"),
])
def test_keywords(tag, name):
    assert dictionary.keyword(tag) == name


def test_implicit_vr_for_ob_or_ow_attribute_is_ow():
    assert dictionary.vr(0x7FE00010) == "OW"  # PS3.5 A.1: implicit-VR Pixel Data is OW


def element(data: bytes, tag: int):
    return next(e for e in parse(data).elements if e.tag == tag)


def test_numeric_rendering_truncates_long_value_lists():
    data = part10(el(0x00091010, "US", struct.pack("<8H", *range(8))))
    assert values.text(data, element(data, 0x00091010)) == r"0\1\2\3\4\5\..."


def test_string_rendering_is_ascii_and_bounded():
    data = part10(el(0x00081030, "LO", b"Chest\x1b[2J CT" + b"x" * 80))
    shown = values.text(data, element(data, 0x00081030))
    assert "\x1b" not in shown and shown.endswith("...") and len(shown) == 40


@pytest.mark.parametrize("vr,raw,expected", [
    ("IS", rb"12\13 ", 12),  # multi-valued: the first value counts
    ("DS", b"1e400", None),  # overflows float: no number, no crash
    ("IS", b"abc ", None),
    ("US", b"\x07", None),  # too short for a US value
])
def test_number_parsing_is_defensive(vr, raw, expected):
    data = part10(el(0x00091010, vr, raw))
    assert values.number(data, element(data, 0x00091010)) == expected


def test_map_of_deflated_file_shows_the_inflated_dataset():
    data = part10(deflate(image(4, 4)), ts=DEFLATED_LE)
    lines = render("x.dcm", data, parse(data))
    assert any("inflated dataset" in line for line in lines)
    assert any("PixelData" in line for line in lines)


def test_map_depth_limit_and_structure_labels():
    data = part10(seq(0x00081140, item(el(0x00081150, "UI", "1.2"))) +
                  image(4, 4, pixel_element=encapsulated(bytes(4))), ts=JPEG_BASELINE)
    deep = render("x.dcm", data, parse(data))
    shallow = render("x.dcm", data, parse(data), max_depth=0)
    assert any("Item #1" in line for line in deep) and not any("Item #1" in line for line in shallow)
    assert any("1 fragment(s), encapsulated" in line for line in deep)


def test_map_describes_a_non_zero_preamble():
    data = part10(preamble=b"VENDOR")
    assert "first bytes 56 45 4e 44" in render("x.dcm", data, parse(data))[4]


def test_text_report_marks_an_incomplete_scan(tmp_path, capsys):
    main(["scan", str(tmp_path / "missing.dcm")])
    err = capsys.readouterr().err
    assert "ERROR" in err and "scan INCOMPLETE" in err


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="no symlinks")
def test_text_report_prints_notes(tmp_path, capsys):
    (tmp_path / "real").mkdir()
    try:
        os.symlink(tmp_path / "real", tmp_path / "link", target_is_directory=True)
    except OSError:
        pytest.skip("creating symlinks is not permitted here")
    main(["scan", str(tmp_path)])
    assert "NOTE" in capsys.readouterr().err
