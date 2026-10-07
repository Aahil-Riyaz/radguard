"""Signature validators: accept the real format, reject the near miss.

Validation is what makes anywhere-in-the-file search usable on pixel data,
so each signature is pinned in both directions.
"""

import struct

import pytest

from builder import fake_elf, fake_pe
from radguard import signatures
from radguard.carving import carve


def zip_entry(method: int = 8, name: bytes = b"payload.bin") -> bytes:
    return b"PK\x03\x04" + struct.pack("<HHHHHIIIHH", 20, 0, method, 0, 0, 0, 0, 0, len(name), 0) + name


def found(data: bytes) -> list[tuple[str, str]]:
    return [(m.signature.kind, m.detail) for m in carve(bytes(16) + data + bytes(64)).matches]


@pytest.mark.parametrize("data,kind,detail", [
    (fake_pe(), "pe", "PE header at 0x50"),
    (fake_elf(), "elf", "64-bit executable"),
    (b"\xcf\xfa\xed\xfe" + struct.pack("<I", 0x01000007), "macho", "x86_64"),
    (b"\xca\xfe\xba\xbe" + struct.pack(">HH", 0, 61), "fat-or-class", "Java class file, version 61.0"),
    (b"\xca\xfe\xba\xbe" + struct.pack(">I", 2), "fat-or-class", "universal binary with 2 architectures"),
    (b"#!/bin/sh -e\necho hi\n", "shebang", "interpreter /bin/sh"),
    (zip_entry(), "zip", "first entry payload.bin"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + bytes(20) + b"\xfe\xff", "ole", ""),
    (b"%PDF-1.7\n", "pdf", "PDF 1.7"),
    (b"{\\rtf1\\ansi", "rtf", ""),
    (b"7z\xbc\xaf\x27\x1c" + bytes(8), "archive", ""),
    (b"<script>", "markup", ""),
])
def test_real_formats_are_confirmed(data, kind, detail):
    assert (kind, detail) in found(data)


@pytest.mark.parametrize("data", [
    b"MZ" + bytes(100),  # no PE header behind the stub
    b"\x7fELF\x02\x01\x01" + bytes(9) + struct.pack("<H", 9),  # e_type 9 does not exist
    b"\x7fELF\x03\x01\x01" + bytes(20),  # EI_CLASS 3 does not exist
    b"\xcf\xfa\xed\xfe" + struct.pack("<I", 0x1234),  # unknown CPU type
    b"\xca\xfe\xba\xbe" + struct.pack(">I", 5000),  # neither a class version nor a sane arch count
    b"#!/" + bytes(40),  # no interpreter path
    zip_entry(method=77),  # no such compression method
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + bytes(40),  # no byte-order mark
    b"%PDF-x.y",
], ids=["mz-stub", "elf-type", "elf-class", "macho-cpu", "cafebabe", "shebang", "zip-method", "ole-bom", "pdf"])
def test_near_misses_are_rejected(data):
    assert found(data) == []


def test_validators_tolerate_truncation_at_the_end_of_the_buffer():
    for sig in signatures.SIGNATURES:
        for magic in sig.scan_magics:
            assert carve(magic).matches == [] or sig.validate is None


def test_preamble_markup_match_ignores_leading_whitespace_and_case():
    match = signatures.match_prefix(b"  \r\n<HTML><body>", 0, 64)
    assert match is not None and match.signature.kind == "markup"


def test_entropy_and_describe_handle_empty_input():
    assert signatures.entropy(b"") == 0.0
    assert signatures.describe(b"", 0, 0) == "empty"
    assert "8.00 bits/byte" in signatures.describe(bytes(range(256)), 0, 256)
