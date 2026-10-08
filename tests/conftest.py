"""Shared fixtures. Every file built here is benign: headers only, no working payloads."""

from __future__ import annotations

import os
import struct

import pytest
from hypothesis import settings

from builder import el, part10
from radguard.checks import ALL_CHECKS
from radguard.context import FileContext
from radguard.findings import FILE, INFLATED
from radguard.rules import RULES

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
    found = [f for check in ALL_CHECKS for f in check(ctx)]
    # Every finding any test produces must be described by the rule catalog (tests/test_rules.py).
    assert {f.check for f in found} <= RULES.keys(), {f.check for f in found} - RULES.keys()
    # ...and must point inside the bytes its offset counts: the file, or the decompressed dataset.
    sizes = {FILE: len(data), INFLATED: len(ctx.parsed.inflated) if ctx.parsed.inflated is not None else -1}
    for f in found:
        assert f.domain in sizes and (f.offset is None or 0 <= f.offset <= sizes[f.domain]), f
    return [f for f in found if f.check.startswith(prefix)]


@pytest.fixture
def write_file(tmp_path):
    def _write(name: str, data: bytes) -> str:
        path = tmp_path / name
        path.write_bytes(data)
        return str(path)

    return _write
