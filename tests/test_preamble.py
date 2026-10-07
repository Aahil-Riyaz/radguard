import struct

import pytest

from conftest import build_dicom, build_pe_polyglot
from radguard.findings import Severity
from radguard.scanner import scan_file


def checks_for(path):
    result = scan_file(path)
    assert result.is_dicom
    return [(f.check, f.severity) for f in result.findings if f.check.startswith("preamble.")]


def test_zero_preamble_is_clean(write_file):
    assert checks_for(write_file("clean.dcm", build_dicom())) == []


@pytest.mark.parametrize("tiff", [b"II*\x00", b"MM\x00*"])
def test_tiff_preamble_is_allowed_by_standard(write_file, tiff):
    assert checks_for(write_file("tiff.dcm", build_dicom(tiff + b"\x08\x00\x00\x00"))) == []


def test_pe_polyglot_is_critical(write_file):
    path = write_file("ct_slice_001", build_pe_polyglot())
    result = scan_file(path)
    [finding] = [f for f in result.findings if f.check.startswith("preamble.")]
    assert finding.check == "preamble.pe-polyglot"
    assert finding.severity is Severity.CRITICAL
    with open(path, "rb") as fh:
        fh.seek(finding.offset)
        assert fh.read(4) == b"PE\x00\x00"


def test_mz_without_pe_signature_is_high(write_file):
    path = write_file("mz.dcm", build_pe_polyglot(valid_pe=False))
    assert checks_for(path) == [("preamble.mz-header", Severity.HIGH)]


def test_mz_with_e_lfanew_past_eof_is_high(write_file):
    pre = bytearray(b"MZ".ljust(128, b"\x00"))
    struct.pack_into("<I", pre, 0x3C, 0xFFFFFF00)
    assert checks_for(write_file("mz.dcm", build_dicom(bytes(pre)))) == [
        ("preamble.mz-header", Severity.HIGH)
    ]


@pytest.mark.parametrize(
    ("preamble", "expected"),
    [
        (b"\x7fELF\x02\x01\x01", ("preamble.elf-polyglot", Severity.CRITICAL)),
        (b"\xcf\xfa\xed\xfe", ("preamble.macho-polyglot", Severity.CRITICAL)),
        (b"#!/bin/sh\n", ("preamble.shebang", Severity.HIGH)),
        (b"PK\x03\x04", ("preamble.zip", Severity.HIGH)),
        (b"%PDF-1.7", ("preamble.pdf", Severity.MEDIUM)),
        (b"  <HTML><body>", ("preamble.markup", Severity.HIGH)),
        (b"<svg xmlns=", ("preamble.markup", Severity.HIGH)),
        (b"ACME-SCANNER v2", ("preamble.nonstandard", Severity.LOW)),
    ],
)
def test_signatures(write_file, preamble, expected):
    assert checks_for(write_file("x.dcm", build_dicom(preamble))) == [expected]


def test_non_dicom_files_are_skipped(write_file):
    assert not scan_file(write_file("notes.txt", b"hello world" * 20)).is_dicom
    assert not scan_file(write_file("tiny", b"DICM")).is_dicom
