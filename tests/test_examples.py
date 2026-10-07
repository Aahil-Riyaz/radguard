"""The committed examples, and the README claims built on them, must stay true."""

import importlib.util
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
    "preamble-polyglot.dcm": {"preamble.pe-polyglot"},
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
    assert (tmp_path / "figure.png").read_bytes() == (ROOT / "docs" / "img" / "two-scans-one-file.png").read_bytes()
