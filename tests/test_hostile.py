"""Regression tests for RadGuard's self-audit (docs/security/self-audit.md).

The scanner reads hostile files for a living, so its own robustness is part of
its threat model. Each test is named after the audit finding it pins.
"""

import io
import json
import os
import random
import sys
import threading
import time

import pytest

from builder import el, fake_elf, image, item, part10, seq
from conftest import findings_for
from radguard import report, scanner
from radguard.carving import Budget, carve
from radguard.cli import main
from radguard.dicom import Limits, parse
from radguard.dicom.parser import MAX_ANOMALIES_PER_CODE, MAX_DEPTH_CEILING
from radguard.findings import Finding, Severity
from radguard.output import dumps, safe

RLO, ZWSP, CJK = chr(0x202E), chr(0x200B), chr(0x60A3)  # kept out of the source as literals


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


# RG-14: a file name the console could not encode aborted the text report halfway.

def redirected_stdout(monkeypatch, encoding: str) -> io.TextIOWrapper:
    """stdout as Python sets it up when output is redirected: a code page, errors="strict"."""
    stream = io.TextIOWrapper(io.BytesIO(), encoding=encoding, errors="strict")
    monkeypatch.setattr(sys, "stdout", stream)
    return stream


def written(stream: io.TextIOWrapper) -> str:
    stream.flush()
    return stream.buffer.getvalue().decode(stream.encoding)  # type: ignore[attr-defined]


def hostile_name(tmp_path, data: bytes) -> str:
    """Create a file whose name is not valid Unicode, the way each platform allows it."""
    name = "x\udcffy.dcm" if os.name == "nt" else os.fsdecode(b"x\xffy.dcm")  # NTFS: unpaired surrogate
    try:
        (tmp_path / name).write_bytes(data)
    except (OSError, UnicodeError):
        pytest.skip("this file system rejects names that are not valid Unicode")
    return name


def test_rg14_a_name_the_code_page_cannot_encode_does_not_abort_the_report(tmp_path, monkeypatch):
    evil = part10(image(4, 4)) + fake_elf()
    (tmp_path / f"a{CJK}.dcm").write_bytes(evil)  # sorts first, so a crash would lose the second finding
    (tmp_path / "b.dcm").write_bytes(evil)
    stdout = redirected_stdout(monkeypatch, "cp1252")
    assert main(["scan", str(tmp_path)]) == 1
    text = written(stdout)
    assert f"a\\u{ord(CJK):04x}.dcm" in text and "b.dcm" in text and "findings: critical=2" in text


@pytest.mark.parametrize("fmt,shown", [
    ("text", "x\\udcffy.dcm"),  # escaped for display
    ("json", "x\\\\udcffy.dcm"),  # the same escape, inside a JSON string
    ("sarif", "x%ED%B3%BFy.dcm" if os.name == "nt" else "x%FFy.dcm"),  # the name's exact bytes, percent-encoded
])
def test_rg14_a_name_that_is_not_unicode_does_not_abort_the_report(tmp_path, monkeypatch, fmt, shown):
    hostile_name(tmp_path, part10(image(4, 4)) + fake_elf())
    stdout = redirected_stdout(monkeypatch, "utf-8")  # Linux CI: UTF-8, errors="strict"
    assert main(["scan", str(tmp_path), "--format", fmt]) == 1
    assert shown in written(stdout)


def test_rg14_safe_escapes_surrogates():
    assert safe("x\udcffy") == "x\\udcffy"
    assert safe("x\udcffy").encode("utf-8")  # always encodable


# RG-15: an invalid file name made the whole JSON report invalid for strict parsers.

def strings(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for k, v in node.items():
            yield k
            yield from strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from strings(v)


@pytest.mark.parametrize("fmt", ["json", "sarif"])
def test_rg15_reports_stay_valid_unicode(tmp_path, capsys, fmt):
    hostile_name(tmp_path, part10(image(4, 4)) + fake_elf())
    main(["scan", str(tmp_path), "--format", fmt])
    out = capsys.readouterr().out
    assert out.isascii()
    for s in strings(json.loads(out)):
        s.encode("utf-8")  # raises on a lone surrogate, as strict JSON parsers do


def test_rg15_dumps_escapes_surrogates_in_keys_and_values():
    decoded = json.loads(dumps({"x\udc80": ["a\udcffb", 1, None, ("t\ud800",)]}))
    assert decoded == {"x\\udc80": ["a\\udcffb", 1, None, ["t\\ud800"]]}


# RG-16: an unexpected exception exited with status 1, the "findings" status.

def test_rg16_an_internal_error_is_reported_as_incomplete(write_file, monkeypatch, capsys):
    def explode(_):
        raise RuntimeError(f"boom{RLO}")
    monkeypatch.setattr(report, "to_text", explode)
    assert main(["scan", write_file("a.dcm", part10(image(4, 4)))]) == 3
    err = capsys.readouterr().err
    assert "internal error" in err and "boom\\u202e" in err and RLO not in err


def test_rg16_a_check_that_crashes_on_output_still_cannot_look_clean(write_file, monkeypatch, capsys):
    monkeypatch.setattr(report, "diagnostics", lambda _: (_ for _ in ()).throw(KeyError("x")))
    assert main(["scan", write_file("a.dcm", part10(image(4, 4)))]) == 3


# RG-17: a Git LFS pointer was skipped as "not DICOM", so CI that checked out without LFS passed a scan
# that never saw the files.

LFS_POINTER = b"version https://git-lfs.github.com/spec/v1\noid sha256:" + b"4d7a" * 16 + b"\nsize 16782\n"


def test_rg17_an_lfs_pointer_makes_the_scan_incomplete(write_file, capsys):
    assert main(["scan", write_file("ct.dcm", LFS_POINTER), "--format", "json"]) == 3
    captured = capsys.readouterr()
    (error,) = json.loads(captured.out)["errors"]
    assert error["error"].startswith("Git LFS pointer") and "lfs: true" in error["error"]
    assert "Git LFS pointer" in captured.err


def test_rg17_map_reports_an_lfs_pointer(write_file, capsys):
    assert main(["map", write_file("ct.dcm", LFS_POINTER)]) == 3
    assert "Git LFS pointer" in capsys.readouterr().err


@pytest.mark.parametrize("data", [
    b"see version https://git-lfs.github.com/spec/v1\n",  # mentions LFS, is not a pointer
    LFS_POINTER.replace(b"\noid sha256:", b"\nhash:"),  # no object id
    LFS_POINTER.replace(b"\nsize ", b"\nlength "),  # no size
    LFS_POINTER + b"x" * (1024 - len(LFS_POINTER)),  # pointers are under 1024 bytes
])
def test_rg17_only_real_pointers_count(write_file, data):
    assert main(["scan", write_file("other", data)]) == 0


def test_rg17_largest_pointer_still_counts(write_file):
    assert main(["scan", write_file("ct.dcm", LFS_POINTER + b"x" * (1023 - len(LFS_POINTER)))]) == 3


def test_rg16_a_closed_pipe_is_reported_as_incomplete(write_file, monkeypatch):
    class ClosedPipe(io.StringIO):
        def write(self, _):
            raise BrokenPipeError(32, "Broken pipe")
    monkeypatch.setattr(sys, "stdout", ClosedPipe())
    assert main(["scan", write_file("a.dcm", part10(image(4, 4)))]) == 3


# Algorithmic-complexity bounds: pathological inputs must finish quickly.

@pytest.mark.parametrize("filler", [b"MZ", b"#!/", b"PK\x03\x04", b"\x7fELF"])
def test_signature_floods_finish_quickly(filler):
    blob = part10(image(4, 4)) + filler * (2_000_000 // len(filler))
    start = time.perf_counter()
    findings_for(blob)
    assert time.perf_counter() - start < 20
