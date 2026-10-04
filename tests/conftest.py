"""Synthetic DICOM builders. Every fixture is benign: headers only, no real payloads."""

from __future__ import annotations

import struct

import pytest

EXPLICIT_VR_LE = b"1.2.840.10008.1.2.1\x00"


def build_dicom(preamble: bytes = b"", body: bytes = b"") -> bytes:
    """Minimal Part 10 byte stream: preamble + DICM + (0002,0010) TransferSyntaxUID + body."""
    assert len(preamble) <= 128
    meta = struct.pack("<HH2sH", 0x0002, 0x0010, b"UI", len(EXPLICIT_VR_LE)) + EXPLICIT_VR_LE
    return preamble.ljust(128, b"\x00") + b"DICM" + meta + body


def build_pe_polyglot(valid_pe: bool = True) -> bytes:
    """MZ header in the preamble whose e_lfanew points into the dataset, like CVE-2019-11687."""
    # Hide "PE\0\0" inside an OB element value, as a real polyglot would.
    payload = b"PE\x00\x00" if valid_pe else b"NOPE"
    element = struct.pack("<HH2sHI", 0x0009, 0x1010, b"OB", 0, 16) + b"\x00" * 8 + payload + b"\x00" * 4
    data = bytearray(build_dicom(b"MZ", element))
    struct.pack_into("<I", data, 0x3C, data.index(payload))
    return bytes(data)


@pytest.fixture
def write_file(tmp_path):
    def _write(name: str, data: bytes) -> str:
        path = tmp_path / name
        path.write_bytes(data)
        return str(path)

    return _write
