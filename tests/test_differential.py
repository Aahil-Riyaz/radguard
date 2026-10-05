"""Parser differentials, proven against a real DICOM implementation (pydicom).

Each test builds one file, shows what pydicom -- the library most Python
medical-imaging and AI pipelines use to load DICOM -- actually does with it,
and shows that RadGuard flags it. These are not hypothetical: if pydicom's
behaviour changes, these tests fail and the documentation must change too.
"""

import io
import warnings

import pytest

from builder import EXPLICIT_LE, PIXEL_DATA, el, fake_pe, image, part10
from conftest import findings_for
from radguard.dicom import parse

pydicom = pytest.importorskip("pydicom")
pytest.importorskip("numpy")

CLEAN = bytes(64)
TAMPERED = bytes([0] * 27 + [255] * 10 + [0] * 27)  # a bright 'lesion' in the middle


def read(data):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return pydicom.dcmread(io.BytesIO(data))


def pixels(ds):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return ds.pixel_array


def checks(data):
    return {f.check for f in findings_for(data)}


def test_two_images_one_file():
    data = part10(image(8, 8, CLEAN) + el(PIXEL_DATA, "OB", TAMPERED))
    # pydicom silently keeps the LAST Pixel Data element: it sees the lesion.
    assert pixels(read(data)).tobytes() == TAMPERED
    # A reader that keeps the first copy sees a clean scan.
    first = next(e for e in parse(data).elements if e.tag == PIXEL_DATA)
    assert data[first.value_offset : first.end] == CLEAN
    assert "pixels.duplicate-pixel-data" in checks(data)


def test_slack_bytes_become_extra_frames():
    attacker_frame = bytes([200]) * 64
    data = part10(image(8, 8, CLEAN + attacker_frame))  # header describes ONE 8x8 frame
    arr = pixels(read(data))
    assert arr.shape == (2, 8, 8)  # pydicom returns a second, attacker-controlled frame
    assert (arr[1] == 200).all()
    assert "pixels.slack" in checks(data)


def test_appended_executable_becomes_invented_attributes():
    data = part10(image(8, 8)) + fake_pe()
    ds = read(data)  # no error, no warning
    invented = [e.tag for e in ds if e.tag.group == 0x5A4D]  # 'MZ' read as a group number
    assert invented, "pydicom parsed the executable's bytes as DICOM attributes"
    assert "structure.hidden-payload" in checks(data)


def test_transfer_syntax_mismatch_is_silently_tolerated():
    data = part10(image(8, 8, implicit=True), ts=EXPLICIT_LE)
    with pytest.warns(UserWarning, match="Expected explicit VR, but found implicit VR"):
        ds = pydicom.dcmread(io.BytesIO(data))
    assert ds.Rows == 8  # decoded anyway; a strict reader would fail
    assert "structure.transfer-syntax-mismatch" in checks(data)


def test_duplicate_attribute_last_one_wins():
    data = part10(el(0x00100010, "PN", "ALICE") + el(0x00100010, "PN", "MALLORY"))
    assert str(read(data).PatientName) == "MALLORY"
    assert "structure.duplicate-tag" in checks(data)
