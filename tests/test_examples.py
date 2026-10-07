"""The committed examples, and the README claims built on them, must stay true."""

import importlib.util
import struct
import zlib
from pathlib import Path

import pytest

from radguard.scanner import scan_file

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"

# Exactly what the README says each example produces: no more, no less.
EXPECTED = {
    "clean.dcm": set(),
    "two-scans-one-file.dcm": {"pixels.duplicate-pixel-data"},
    "hidden-frame.dcm": {"pixels.slack"},
    "appended-executable.dcm": {"structure.hidden-payload"},
    # The PE header hides in a private element that no Private Creator reserves.
    "preamble-polyglot.dcm": {"preamble.pe-polyglot", "private.orphan-element"},
}


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_example_produces_exactly_the_documented_findings(name):
    result = scan_file(str(EXAMPLES / name))
    assert result.is_dicom and result.error is None
    assert {f.check for f in result.findings} == EXPECTED[name]


def test_every_example_is_covered():
    assert {p.name for p in EXAMPLES.glob("*.dcm")} == set(EXPECTED)


def test_examples_and_figure_are_reproducible(tmp_path):
    pytest.importorskip("pydicom")
    pytest.importorskip("numpy")
    spec = importlib.util.spec_from_file_location("make_examples", ROOT / "scripts" / "make_examples.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.main(out=tmp_path / "examples", fig=tmp_path / "figure.png")
    for name in EXPECTED:
        assert (tmp_path / "examples" / name).read_bytes() == (EXAMPLES / name).read_bytes(), name
    # Compare decoded pixels, not compressed bytes: zlib builds (classic zlib, zlib-ng) emit
    # different but equally valid deflate streams for the same image.
    regenerated = png_image((tmp_path / "figure.png").read_bytes())
    assert regenerated == png_image((ROOT / "docs" / "img" / "two-scans-one-file.png").read_bytes())


def png_image(data: bytes) -> tuple[bytes, bytes]:
    """The IHDR (dimensions and format) and the decompressed scanlines of a PNG."""
    assert data.startswith(b"\x89PNG\r\n\x1a\n")
    pos, header, idat = 8, b"", b""
    while pos < len(data):
        (length,), kind = struct.unpack_from(">I", data, pos), data[pos + 4 : pos + 8]
        body = data[pos + 8 : pos + 8 + length]
        if kind == b"IHDR":
            header = body
        elif kind == b"IDAT":
            idat += body
        pos += 12 + length
    return header, zlib.decompress(idat)
