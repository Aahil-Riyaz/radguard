"""Regression tests for RadGuard's self-audit (docs/security/self-audit.md).

The scanner reads hostile files for a living, so its own robustness is part of
its threat model. Each test is named after the audit finding it pins.
"""

import os
import random
import threading
import time

import pytest

from builder import el, fake_elf, image, item, part10, seq
from conftest import findings_for
from radguard import scanner
from radguard.carving import Budget, carve
from radguard.cli import main
from radguard.dicom import Limits, parse
from radguard.dicom.parser import MAX_ANOMALIES_PER_CODE, MAX_DEPTH_CEILING
from radguard.findings import Finding, Severity
from radguard.output import safe

RLO, ZWSP = chr(0x202E), chr(0x200B)  # kept out of the source as literals


def by_check(data):
    return {f.check: f for f in findings_for(data)}


# RG-01: a fixed candidate cap was an evasion primitive.

def test_rg01_decoy_flood_is_reported_not_silent():
    data = part10(image(4, 4)) + b"MZ" * 40_000 + fake_elf()
    found = by_check(data)
    incomplete = found["structure.analysis-incomplete"]
    assert incomplete.severity is Severity.HIGH
    assert "exhaust analysis" in incomplete.title


def test_rg01_flooding_one_signature_does_not_starve_the_others():
    data = part10(image(4, 4)) + b"MZ" * 40_000 + fake_elf()
    assert "ELF executable" in by_check(data)["structure.hidden-payload"].title


# RG-02: a fixed search window was a silent blind spot.

def test_rg02_bytes_beyond_the_window_are_reported_as_uninspected():
    buf = bytes(4096) + fake_elf()
    index = carve(buf, Budget(max_bytes=1024))
    assert index.matches == []
    assert [e.reason for e in index.exhausted] == ["size"]


# RG-03: opening a FIFO blocked the scanner forever.

@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are POSIX-only")
def test_rg03_fifo_does_not_hang_the_scan(tmp_path):
    os.mkfifo(tmp_path / "pipe")
    results = []
    worker = threading.Thread(target=lambda: results.extend(scanner.scan_paths([str(tmp_path)])), daemon=True)
    worker.start()
    worker.join(timeout=10)
    assert not worker.is_alive(), "scanner blocked on a FIFO"
    assert [r.is_dicom for r in results] == [False]


# RG-04: a mapped file truncated mid-scan raises SIGBUS on POSIX.

def test_rg04_ordinary_files_are_read_into_private_memory(write_file):
    path = write_file("a.dcm", part10(image(4, 4)))
    with scanner.open_dicom(path) as ctx:
        assert isinstance(ctx.buf, bytes)


def test_rg04_only_files_above_the_limit_are_mapped(write_file, monkeypatch):
    monkeypatch.setattr(scanner, "READ_LIMIT", 200)
    path = write_file("a.dcm", part10(image(4, 4)))
    with scanner.open_dicom(path) as ctx:
        assert not isinstance(ctx.buf, bytes)
        assert ctx.parsed.size == os.path.getsize(path)


# RG-05: attacker-controlled names and values reached the terminal raw.

@pytest.mark.parametrize("raw,escaped", [
    ("a\x1b[2Jb", "a\\x1b[2Jb"),  # ANSI escape: clear screen
    ("x\x07\x08y", "x\\x07\\x08y"),  # bell, backspace
    (f"scan{RLO}gpj.dcm", "scan\\u202egpj.dcm"),  # bidi override (Trojan Source)
    (f"a{ZWSP}b", "a\\u200bb"),  # zero-width space
    ("tab\tok", "tab\tok"),
])
def test_rg05_output_is_sanitised(raw, escaped):
    assert safe(raw) == escaped


def test_rg05_cli_never_prints_raw_bidi_controls(write_file, capsys):
    write_file(f"scan{RLO}gpj.dcm", part10(image(4, 4)) + fake_elf())
    main(["scan", os.path.dirname(write_file("x.txt", b"x"))])
    out = capsys.readouterr().out
    assert RLO not in out and "\\u202e" in out


# RG-06: one malformed file could produce unbounded anomalies.

def test_rg06_anomaly_flood_is_capped_and_summarised():
    flood = b"".join(el(0x00091000 + i, "OB", b"x") for i in range(1, 2001))  # 2,000 odd lengths
    parsed = parse(part10(flood))
    assert sum(a.code == "odd-length" for a in parsed.anomalies) == MAX_ANOMALIES_PER_CODE
    [summary] = [a for a in parsed.anomalies if a.code == "suppressed"]
    assert "1,950 more 'odd-length'" in summary.message


def test_rg06_finding_flood_is_capped_per_check(write_file):
    def noisy(ctx):
        return [Finding("test.noise", Severity.LOW, "noise", "", ctx.path) for _ in range(500)]

    result = scanner.scan_file(write_file("a.dcm", part10()), checks=[noisy])
    assert sum(f.check == "test.noise" for f in result.findings) == scanner.MAX_FINDINGS_PER_CHECK
    assert result.findings[-1].check == "scan.findings-suppressed"


def test_rg06_crashing_check_is_isolated(write_file):
    def broken(ctx):
        raise RuntimeError("boom")

    result = scanner.scan_file(write_file("a.dcm", part10()), checks=[broken])
    assert result.is_dicom and "boom" in result.error


# RG-07: an unvalidated depth limit could become a RecursionError.

def test_rg07_depth_limit_is_validated():
    with pytest.raises(ValueError):
        Limits(max_depth=MAX_DEPTH_CEILING + 1)


def test_rg07_deepest_permitted_parse_stays_clear_of_the_recursion_limit():
    payload = el(0x00100010, "PN", "X")
    for _ in range(MAX_DEPTH_CEILING + 50):
        payload = seq(0x00081140, item(payload, undefined=True), undefined=True)
    parsed = parse(part10(payload), Limits(max_depth=MAX_DEPTH_CEILING))
    assert "max-depth" in [a.code for a in parsed.anomalies]


# RG-09: weak anywhere-signatures fired on random pixel data (alert fatigue).

def test_rg09_validated_signatures_ignore_random_data():
    noise = random.Random(9).randbytes(16 << 20)  # 16 MiB, like a large compressed series
    assert carve(noise).matches == []


# Algorithmic-complexity bounds: pathological inputs must finish quickly.

@pytest.mark.parametrize("filler", [b"MZ", b"#!/", b"PK\x03\x04", b"\x7fELF"])
def test_signature_floods_finish_quickly(filler):
    blob = part10(image(4, 4)) + filler * (2_000_000 // len(filler))
    start = time.perf_counter()
    findings_for(blob)
    assert time.perf_counter() - start < 20
