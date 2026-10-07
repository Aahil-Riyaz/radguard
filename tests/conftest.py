"""Shared fixtures. Every file built here is benign: headers only, no working payloads."""

from __future__ import annotations

import os
import struct

import pytest
from hypothesis import settings

from builder import el, part10
from radguard.checks import ALL_CHECKS
from radguard.context import FileContext

settings.register_profile("default", max_examples=400)
settings.register_profile("quick", max_examples=50)  # mutation testing: thousands of suite runs
settings.register_profile("deep", max_examples=25_000)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "default"))


def build_dicom(preamble: bytes = b"", body: bytes = b"") -> bytes:
    """A conforming Part 10 file: preamble + DICM + File Meta + `body`."""
    return part10(body, preamble=preamble)


def build_pe_polyglot(valid_pe: bool = True) -> bytes:
    """MZ header in the preamble whose e_lfanew points into the dataset, like CVE-2019-11687."""
    # Hide "PE\0\0" inside an OB element value, as a real polyglot would.
    payload = b"PE\x00\x00" if valid_pe else b"NOPE"
    data = bytearray(build_dicom(b"MZ", el(0x00091010, "OB", bytes(8) + payload + bytes(4))))
    struct.pack_into("<I", data, 0x3C, data.index(payload))
    return bytes(data)


def findings_for(data: bytes, prefix: str = "") -> list:
    """Run every check over in-memory bytes and return findings whose id starts with `prefix`."""
    ctx = FileContext("<memory>", data, len(data))
    return [f for check in ALL_CHECKS for f in check(ctx) if f.check.startswith(prefix)]


@pytest.fixture
def write_file(tmp_path):
    def _write(name: str, data: bytes) -> str:
        path = tmp_path / name
        path.write_bytes(data)
        return str(path)

    return _write
