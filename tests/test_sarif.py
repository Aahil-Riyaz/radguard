"""SARIF 2.1.0 output: structure GitHub code scanning relies on, and the fail-closed contract."""

import json
from pathlib import Path

import pytest

from conftest import build_dicom, build_pe_polyglot
from radguard.cli import main
from radguard.findings import Finding, Severity
from radguard.sarif import SARIF_SCHEMA, SARIF_VERSION, artifact_uri, build_sarif


def _finding(check="preamble.pe-polyglot", severity=Severity.CRITICAL, path="a.dcm", offset=0, refs=()):
    return Finding(check, severity, "A title", "Some detail", path, offset, tuple(refs))


def test_envelope_identifies_sarif_2_1_0():
    log = build_sarif([], [], [])
    assert log["version"] == SARIF_VERSION == "2.1.0"
    assert log["$schema"] == SARIF_SCHEMA
    (run,) = log["runs"]
    assert run["tool"]["driver"]["name"] == "radguard"
    assert run["results"] == []
    assert run["invocations"][0]["executionSuccessful"] is True


def test_one_rule_per_check_and_results_point_at_it():
    findings = [
        _finding("preamble.pe-polyglot", path="a.dcm"),
        _finding("preamble.pe-polyglot", path="b.dcm"),
        _finding("pixels.duplicate-pixel-data", Severity.HIGH, path="c.dcm", offset=0x182),
    ]
    (run,) = build_sarif(findings, [], [])["runs"]
    rules = run["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == ["preamble.pe-polyglot", "pixels.duplicate-pixel-data"]
    for result in run["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]


@pytest.mark.parametrize(
    ("severity", "level", "score"),
    [
        (Severity.CRITICAL, "error", "9.5"),
        (Severity.HIGH, "error", "8.0"),
        (Severity.MEDIUM, "warning", "5.5"),
        (Severity.LOW, "note", "3.0"),
        (Severity.INFO, "note", "0.5"),
    ],
)
def test_severity_maps_to_level_and_github_security_severity(severity, level, score):
    (run,) = build_sarif([_finding(severity=severity)], [], [])["runs"]
    (result,) = run["results"]
    (rule,) = run["tool"]["driver"]["rules"]
    assert result["level"] == rule["defaultConfiguration"]["level"] == level
    assert rule["properties"]["security-severity"] == score


def test_region_is_line_one_with_the_real_byte_offset():
    (run,) = build_sarif([_finding(offset=0x418E), _finding(path="b.dcm", offset=None)], [], [])["runs"]
    first, second = (r["locations"][0]["physicalLocation"]["region"] for r in run["results"])
    assert first == {"startLine": 1, "byteOffset": 0x418E}
    assert second == {"startLine": 1}


def test_references_become_help_uri_and_result_property():
    url = "https://nvd.nist.gov/vuln/detail/CVE-2019-11687"
    (run,) = build_sarif([_finding(refs=[url, "https://example.org/second"])], [], [])["runs"]
    assert run["tool"]["driver"]["rules"][0]["helpUri"] == url
    assert run["results"][0]["properties"]["references"] == [url, "https://example.org/second"]
    (bare,) = build_sarif([_finding()], [], [])["runs"]
    assert "helpUri" not in bare["tool"]["driver"]["rules"][0]
    assert "references" not in bare["results"][0]["properties"]


def test_artifact_uri_is_repo_relative_posix_inside_base(tmp_path):
    nested = tmp_path / "studies" / "ct" / "a.dcm"
    nested.parent.mkdir(parents=True)
    nested.write_bytes(b"")
    assert artifact_uri(str(nested), tmp_path) == "studies/ct/a.dcm"


def test_artifact_uri_outside_base_is_an_absolute_file_uri(tmp_path):
    base = tmp_path / "repo"
    base.mkdir()
    outside = tmp_path / "elsewhere" / "a.dcm"
    assert artifact_uri(str(outside), base) == Path(outside).resolve().as_uri()
    assert artifact_uri(str(outside), base).startswith("file:///")


def test_incomplete_scan_is_reported_not_hidden():
    errors = [{"path": "gone.dcm", "error": "permission denied"}]
    notes = [{"path": "link.dcm", "note": "symlink skipped"}]
    (run,) = build_sarif([], errors, notes)["runs"]
    invocation = run["invocations"][0]
    assert invocation["executionSuccessful"] is False
    levels = [n["level"] for n in invocation["toolExecutionNotifications"]]
    assert levels == ["error", "note"]
    assert "permission denied" in invocation["toolExecutionNotifications"][0]["message"]["text"]


def test_cli_emits_valid_sarif_and_keeps_exit_codes(tmp_path, write_file, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    write_file("clean.dcm", build_dicom())
    write_file("evil.dcm", build_pe_polyglot())

    assert main(["scan", ".", "--format", "sarif"]) == 1  # a critical finding still fails the build

    log = json.loads(capsys.readouterr().out)
    (run,) = log["runs"]
    assert log["version"] == "2.1.0"
    assert "preamble.pe-polyglot" in {r["ruleId"] for r in run["results"]}
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in run["results"]}
    assert uris == {"evil.dcm"}  # relative, so GitHub can attach alerts; the clean file has none


def test_cli_missing_path_exits_3_and_marks_run_unsuccessful(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main(["scan", "missing.dcm", "--format", "sarif"]) == 3
    log = json.loads(capsys.readouterr().out)
    assert log["runs"][0]["invocations"][0]["executionSuccessful"] is False


def test_hostile_file_name_cannot_inject_control_characters(tmp_path, write_file, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    bidi_override = chr(0x202E)  # "Trojan Source" style; built at runtime so this file stays ASCII
    write_file(bidi_override + "gpj.dcm", build_pe_polyglot())
    main(["scan", ".", "--format", "sarif"])
    out = capsys.readouterr().out
    assert bidi_override not in out  # json.dumps escapes it as \u202e
    assert r"\u202e" in out  # the escaped, visible form
    json.loads(out)
