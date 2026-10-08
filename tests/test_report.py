"""The scan report: gathered once, rendered as text or JSON, delivered to stdout or a file."""

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from itertools import count

import pytest

from builder import fake_elf, fake_pe, image, part10
from radguard import cli, report
from radguard.cli import main
from radguard.findings import Finding, Severity
from radguard.scanner import FileResult

T0 = datetime(2026, 10, 8, 9, 30, 0, 123456, tzinfo=timezone.utc)


def ticking_clock():
    ticks = count()
    return lambda: T0 + timedelta(seconds=next(ticks))


def finding(check: str, severity: Severity, path: str, offset: int | None = None) -> Finding:
    return Finding(check, severity, "title", "detail", path, offset)


# -- collecting ---------------------------------------------------------------------------------

def test_collect_counts_and_orders_everything():
    results = [
        FileResult("b.dcm", True, [finding("x.low", Severity.LOW, "b.dcm", 5)], size=10, sha256="bb"),
        FileResult("a.dcm", True, [finding("x.crit", Severity.CRITICAL, "a.dcm", 9),
                                   finding("x.crit", Severity.CRITICAL, "a.dcm", None)], size=20, sha256="aa"),
        FileResult("clean.dcm", True),
        FileResult("notes.txt", False),
        FileResult("gone.dcm", False, error="No such file"),
        FileResult("link", False, note="symbolic link to a directory: not followed"),
    ]
    r = report.collect(results, ticking_clock())
    assert (r.files, r.dicom, r.skipped) == (5, 3, 1)
    assert [(f.path, f.offset) for f in r.findings] == [("a.dcm", None), ("a.dcm", 9), ("b.dcm", 5)]
    assert r.counts() == {"critical": 2, "high": 0, "medium": 0, "low": 1, "info": 0}
    assert list(r.counts()) == ["critical", "high", "medium", "low", "info"]
    assert r.errors == [report.PathMessage("gone.dcm", "No such file")]
    assert r.notes == [report.PathMessage("link", "symbolic link to a directory: not followed")]
    assert r.artifacts == {"a.dcm": report.Artifact("a.dcm", 20, "aa"), "b.dcm": report.Artifact("b.dcm", 10, "bb")}
    assert (r.started, r.finished) == (T0, T0 + timedelta(seconds=2))  # finished is read after the scan
    assert not r.complete


def test_threshold_is_inclusive():
    r = report.collect([FileResult("a", True, [finding("x", Severity.MEDIUM, "a")])], ticking_clock())
    assert r.reaches(Severity.MEDIUM) and not r.reaches(Severity.HIGH)


@pytest.mark.parametrize("moment,text", [
    (T0, "2026-10-08T09:30:00.123Z"),
    (T0.replace(microsecond=999999), "2026-10-08T09:30:00.999Z"),  # truncated, never rounded into the next second
    (T0.replace(microsecond=0), "2026-10-08T09:30:00.000Z"),
    (datetime(2026, 10, 8, 11, 0, tzinfo=timezone(timedelta(hours=2))), "2026-10-08T09:00:00.000Z"),
])
def test_timestamps_are_utc_with_milliseconds(moment, text):
    assert report.timestamp(moment) == text


# -- what the scanner records about each file -------------------------------------------------------

def test_files_with_findings_are_identified_by_the_bytes_examined(write_file, capsys):
    data = part10(image(4, 4)) + fake_pe()
    path = write_file("evil.dcm", data)
    write_file("clean.dcm", part10(image(4, 4)))
    main(["scan", os.path.dirname(path), "--format", "json"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["artifacts"] == [{"path": path, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}]
    assert doc["started"].endswith("Z") and doc["started"] <= doc["finished"]


def test_json_lists_errors_and_notes(tmp_path, capsys):
    main(["scan", str(tmp_path / "missing.dcm"), "--format", "json"])
    captured = capsys.readouterr()
    doc = json.loads(captured.out)
    assert doc["errors"][0]["path"].endswith("missing.dcm") and doc["notes"] == []
    assert "scan INCOMPLETE" in captured.err  # diagnostics go to stderr in every format


# -- delivering the report ----------------------------------------------------------------------

@pytest.mark.parametrize("fmt", ["text", "json", "sarif"])
def test_output_file_matches_standard_output(write_file, tmp_path, capsys, fmt):
    target = write_file("evil.dcm", part10(image(4, 4)) + fake_elf())
    out = tmp_path / "report.out"
    assert main(["scan", target, "--format", fmt, "-o", str(out)]) == 1
    assert capsys.readouterr().out == ""
    written = out.read_bytes()
    assert b"\r\n" not in written and written.decode("utf-8")  # UTF-8 with LF, whatever the platform
    main(["scan", target, "--format", fmt])
    stdout = capsys.readouterr().out
    if fmt == "text":
        assert written.decode() == stdout.replace("\r\n", "\n")
    else:  # timestamps differ between the two runs; everything else is identical
        a, b = json.loads(written), json.loads(stdout)
        assert drop_times(a) == drop_times(b)


def drop_times(doc):
    if isinstance(doc, dict):
        return {k: drop_times(v) for k, v in doc.items() if k not in {"started", "finished", "startTimeUtc",
                                                                         "endTimeUtc"}}
    if isinstance(doc, list):
        return [drop_times(v) for v in doc]
    return doc


def test_output_file_is_replaced_whole(write_file, tmp_path):
    out = tmp_path / "report.json"
    out.write_text("previous report, much longer than the new one " * 1000)
    main(["scan", write_file("a.dcm", part10(image(4, 4))), "--format", "json", "-o", str(out)])
    assert json.loads(out.read_text())["summary"]["files"] == 1
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".radguard-")] == []


def test_unwritable_output_makes_the_scan_incomplete(write_file, tmp_path, capsys):
    target = write_file("evil.dcm", part10(image(4, 4)) + fake_elf())
    (tmp_path / "a-directory").mkdir()
    assert main(["scan", target, "-o", str(tmp_path / "a-directory")]) == 3
    assert "cannot write" in capsys.readouterr().err
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".radguard-")] == []


def test_a_failed_write_removes_the_temporary_file(tmp_path, monkeypatch):
    def fail(src, dst):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(os, "replace", fail)
    with pytest.raises(OSError):
        cli._write_atomically(str(tmp_path / "r.json"), "{}")
    assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_output_file_is_private_to_its_owner(write_file, tmp_path):
    out = tmp_path / "r.json"
    main(["scan", write_file("a.dcm", part10(image(4, 4))), "--format", "json", "-o", str(out)])
    assert out.stat().st_mode & 0o077 == 0


# -- the rule catalog on the command line --------------------------------------------------------

def test_rules_command_lists_every_rule(capsys):
    from radguard.rules import RULES
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    assert all(rule_id in out for rule_id in RULES) and f"{len(RULES)} rules" in out


def test_rules_command_prints_the_reference(capsys):
    from radguard.rules import reference
    assert main(["rules", "--markdown"]) == 0
    assert capsys.readouterr().out.replace("\r\n", "\n") == reference()
