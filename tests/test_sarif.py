"""SARIF output: valid against the official schema, within GitHub's limits, and inert when the input is hostile."""

import hashlib
import json
import ntpath
import posixpath
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote_to_bytes

import jsonschema
import pytest
from hypothesis import given
from hypothesis import strategies as st

from builder import DEFLATED_LE, deflate, el, fake_elf, image, part10
from radguard import rules, sarif
from radguard.cli import main
from radguard.findings import Finding, Severity
from radguard.output import dumps, safe
from radguard.report import Artifact, PathMessage, ScanReport

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "tests/schemas/sarif-schema-2.1.0.json"
SCHEMA_SHA256 = "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e"  # OASIS errata01, as published
SAMPLE = ROOT / "docs/sample-report.sarif"
T0 = datetime(2026, 10, 9, 8, 0, tzinfo=timezone.utc)
URI_CHARS = re.compile(r"[A-Za-z0-9._~/%-]*")  # RFC 3986 unreserved characters, "/" and percent-escapes


@pytest.fixture(scope="module")
def validator():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.Draft4Validator.check_schema(schema)
    return jsonschema.Draft4Validator(schema, format_checker=jsonschema.FormatChecker())


def valid(doc, validator):
    """Round-trip through the real serialiser, then validate: what is checked is what would be written."""
    decoded = json.loads(dumps(doc))
    errors = [f"{list(e.path)}: {e.message}" for e in validator.iter_errors(decoded)]
    assert not errors, errors[:5]
    return decoded


def scan_report(findings=(), errors=(), notes=(), artifacts=()):
    return ScanReport(started=T0, finished=T0, findings=list(findings), errors=list(errors), notes=list(notes),
                      artifacts={a.path: a for a in artifacts}, files=len(artifacts), dicom=len(artifacts))


def finding(check="preamble.pe-polyglot", severity=None, path="/repo/a.dcm", offset=0, detail="detail"):
    severity = rules.RULES[check].severity if severity is None and check in rules.RULES else severity
    return Finding(check, severity or Severity.MEDIUM, "Title", detail, path, offset)


def to_sarif(report, **kw):
    return sarif.to_sarif(report, "/repo", pathmod=posixpath, **kw)


def the_run(doc):
    assert len(doc["runs"]) == 1  # GitHub rejects several runs of one tool and category
    return doc["runs"][0]


# -- the schema itself ------------------------------------------------------------------------------

def test_vendored_schema_is_the_published_one():
    assert hashlib.sha256(SCHEMA_PATH.read_bytes()).hexdigest() == SCHEMA_SHA256


def test_validator_actually_rejects_invalid_logs(validator):
    doc = to_sarif(scan_report([finding()]))
    the_run(doc)["results"][0]["level"] = "fatal"
    the_run(doc)["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = "a b"
    messages = [e.message for e in validator.iter_errors(json.loads(dumps(doc)))]
    assert any("fatal" in m for m in messages) and any("a b" in m for m in messages)


# -- real scans ---------------------------------------------------------------------------------------

def test_scan_of_the_examples_is_valid(validator, monkeypatch, capsys):
    monkeypatch.chdir(ROOT)
    assert main(["scan", "examples", "--format", "sarif"]) == 1
    run = the_run(valid(json.loads(capsys.readouterr().out), validator))
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in run["results"]}
    assert uris == {"examples/appended-executable.dcm", "examples/hidden-frame.dcm",
                    "examples/preamble-polyglot.dcm", "examples/two-scans-one-file.dcm"}
    for a in run["artifacts"]:
        data = (ROOT / a["location"]["uri"]).read_bytes()
        assert a["hashes"]["sha-256"] == hashlib.sha256(data).hexdigest() and a["length"] == len(data)
    assert run["invocations"][0]["exitCode"] == 1 and run["invocations"][0]["executionSuccessful"] is True


def drop_times(doc):
    if isinstance(doc, dict):
        return {k: drop_times(v) for k, v in doc.items() if k not in {"startTimeUtc", "endTimeUtc"}}
    if isinstance(doc, list):
        return [drop_times(v) for v in doc]
    return doc


def test_sample_report_is_current(monkeypatch, capsys):
    monkeypatch.chdir(ROOT)
    main(["scan", "examples", "--format", "sarif"])
    fresh = json.loads(capsys.readouterr().out)
    assert drop_times(fresh) == drop_times(json.loads(SAMPLE.read_text(encoding="utf-8"))), \
        "regenerate: radguard scan examples --format sarif -o docs/sample-report.sarif"


def test_edge_case_log_for_external_validators_is_valid(validator, tmp_path):
    # CI hands this log to Microsoft's SARIF Multitool; it must keep covering every branch of the writer.
    import importlib.util
    spec = importlib.util.spec_from_file_location("edge", ROOT / "scripts/sarif_edge_cases.py")
    edge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(edge)
    edge.main(str(tmp_path / "edge.sarif"))
    run = the_run(valid(json.loads((tmp_path / "edge.sarif").read_text(encoding="utf-8")), validator))
    levels = {n["descriptor"]["id"]: n["level"] for n in run["invocations"][0]["toolExecutionNotifications"]}
    assert levels == {sarif.PATH_ERROR: "error", sarif.PATH_SKIPPED: "note", sarif.RESULTS_OMITTED: "warning"}
    assert "values.embedded-file/low" in {r["ruleId"] for r in run["results"]}
    assert {r["properties"].get("domain") for r in run["results"]} >= {"file", "inflated"}
    assert any("offset" not in r["properties"] for r in run["results"])  # a finding about a whole file


def test_incomplete_scan_is_a_failed_run(validator, write_file, tmp_path, capsys):
    evil = write_file("evil.dcm", part10(image(4, 4)) + fake_elf())
    assert main(["scan", evil, str(tmp_path / "missing.dcm"), "--format", "sarif"]) == 3
    run = the_run(valid(json.loads(capsys.readouterr().out), validator))
    invocation = run["invocations"][0]
    assert invocation["executionSuccessful"] is False and invocation["exitCode"] == 3
    (note,) = invocation["toolExecutionNotifications"]
    assert note["level"] == "error" and note["descriptor"]["id"] == sarif.PATH_ERROR
    assert note["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].endswith("/missing.dcm")
    assert run["results"]  # findings are still reported


# -- structure ------------------------------------------------------------------------------------------

def test_every_result_points_at_its_own_descriptor(validator):
    findings = [finding(check, offset=n) for n, check in enumerate(sorted(rules.RULES))]
    run = the_run(valid(to_sarif(scan_report(findings)), validator))
    descriptors = run["tool"]["driver"]["rules"]
    assert [d["id"] for d in descriptors[: len(rules.RULES)]] == sorted(rules.RULES)
    for r in run["results"]:
        assert descriptors[r["ruleIndex"]]["id"] == r["ruleId"]


def test_descriptors_carry_what_github_requires_within_its_limits(validator):
    run = the_run(valid(to_sarif(scan_report()), validator))
    for d in run["tool"]["driver"]["rules"]:
        assert d["shortDescription"]["text"] and len(d["shortDescription"]["text"]) <= 1024
        assert d["fullDescription"]["text"] and len(d["fullDescription"]["text"]) <= 1024
        assert d["help"]["text"] and len(d["name"]) <= 255 and d["name"] != d["id"]
        assert "security" in d["properties"]["tags"] and len(d["properties"]["tags"]) <= 10
        assert d["properties"]["precision"] in rules.PRECISIONS
        score = d["properties"]["security-severity"]
        assert isinstance(score, str) and 0.0 < float(score) <= 10.0  # a non-number fails the whole upload
        assert d["helpUri"].startswith("https://")


def test_notification_descriptors_are_complete(validator):
    driver = the_run(valid(to_sarif(scan_report()), validator))["tool"]["driver"]
    assert [n["id"] for n in driver["notifications"]] == [sarif.PATH_ERROR, sarif.PATH_SKIPPED, sarif.RESULTS_OMITTED]
    for n in driver["notifications"]:  # Microsoft's GitHub rule set (GH2012) checks every descriptor
        assert n["shortDescription"]["text"] and n["fullDescription"]["text"] and n["help"]["text"]
    assert driver["notifications"][0]["name"] == "ScanPathError"


def test_binary_regions_only(validator):
    run = the_run(valid(to_sarif(scan_report([finding(offset=0x418E), finding(offset=None)])), validator))
    regions = [r["locations"][0]["physicalLocation"].get("region") for r in run["results"]]
    assert {"byteOffset": 0x418E} in regions and None in regions  # no offset: the finding is about the whole file
    text = dumps(run)
    assert not any(key in text for key in ("startLine", "startColumn", "charOffset", "columnKind"))


def test_severity_mapping_is_inside_github_bands():
    # GitHub: "over 9.0 is critical, from 7.0 to 8.9 is high, from 4.0 to 6.9 is medium and from 0.1 to 3.9 is low".
    score = {k: float(v) for k, v in sarif.SECURITY_SEVERITY.items()}
    assert 9.0 < score[Severity.CRITICAL] <= 10.0
    assert 7.0 <= score[Severity.HIGH] <= 8.9 and 4.0 <= score[Severity.MEDIUM] <= 6.9
    assert 0.1 <= score[Severity.LOW] <= 3.9 and score[Severity.INFO] == 0.0
    assert sarif.LEVELS == {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
                            Severity.LOW: "note", Severity.INFO: "note"}


def test_the_offset_is_in_the_message_because_github_does_not_show_regions():
    (result,) = the_run(to_sarif(scan_report([finding(offset=0x418E)])))["results"]
    assert result["message"]["text"].endswith("Detail. At byte 0x418e of the file")


def test_an_offset_into_the_decompressed_dataset_is_not_a_file_region(validator):
    inflated = Finding("structure.nonzero-padding", Severity.HIGH, "Title", "detail", "/repo/a.dcm", 0x9000,
                       domain="inflated")
    (result,) = the_run(valid(to_sarif(scan_report([inflated])), validator))["results"]
    assert "region" not in result["locations"][0]["physicalLocation"]  # 0x9000 is not a position in the file
    assert result["properties"] == {"severity": "high", "offset": 0x9000, "domain": "inflated"}
    assert result["message"]["text"].endswith("At byte 0x9000 of the decompressed dataset (the file is deflated)")
    as_file = fingerprints(scan_report([finding("structure.nonzero-padding", offset=0x9000)]))
    assert result["partialFingerprints"] != as_file[0]  # the same number in another byte space is another place


def test_a_real_deflated_file(validator, write_file, capsys):
    # The payload sits in trailing padding after 16 KiB of zero pixels, which deflate shrinks to almost nothing,
    # so its offset in the decompressed dataset lies far beyond the end of the file.
    blob = part10(deflate(image(128, 128) + el(0xFFFCFFFC, "OB", fake_elf())), ts=DEFLATED_LE)
    main(["scan", write_file("deflated.dcm", blob), "--format", "sarif"])
    run = the_run(valid(json.loads(capsys.readouterr().out), validator))
    padding = next(r for r in run["results"] if r["ruleId"].startswith("structure.nonzero-padding"))
    assert padding["properties"]["domain"] == "inflated" and padding["properties"]["offset"] > len(blob)
    # The decompressed position is no file position, so the region is the whole file, stated explicitly.
    assert padding["locations"][0]["physicalLocation"]["region"] == {"byteOffset": 0, "byteLength": len(blob)}


def test_a_finding_about_a_whole_file_covers_it_explicitly_when_its_size_is_known(validator):
    art = Artifact("/repo/a.dcm", 1234, "ab" * 32)
    run = the_run(valid(to_sarif(scan_report([finding(offset=None)], artifacts=[art])), validator))
    assert run["results"][0]["locations"][0]["physicalLocation"]["region"] == {"byteOffset": 0, "byteLength": 1234}


def test_artifacts_are_identified_by_hash(validator):
    art = Artifact("/repo/a.dcm", 1234, "ab" * 32)
    run = the_run(valid(to_sarif(scan_report([finding()], artifacts=[art])), validator))
    (artifact,) = run["artifacts"]
    assert artifact == {"location": {"uri": "a.dcm", "uriBaseId": "%SRCROOT%"}, "length": 1234,
                        "mimeType": "application/dicom", "hashes": {"sha-256": "ab" * 32}, "roles": ["analysisTarget"]}
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["index"] == 0


def test_no_absolute_path_of_the_scanning_machine(validator):
    run = the_run(valid(to_sarif(scan_report([finding()])), validator))
    assert "uri" not in run["originalUriBaseIds"]["%SRCROOT%"] and "/repo" not in dumps(run)


def test_cwe_taxonomy_is_consistent(validator):
    run = the_run(valid(to_sarif(scan_report()), validator))
    (taxonomy,) = run["taxonomies"]
    taxa = {t["id"] for t in taxonomy["taxa"]}
    assert taxa == {str(n) for n in rules.CWE_NAMES}
    assert run["tool"]["driver"]["supportedTaxonomies"] == [{"name": "CWE", "guid": taxonomy["guid"]}]
    for d in run["tool"]["driver"]["rules"]:
        for rel in d.get("relationships", []):
            assert rel["target"]["id"] in taxa and rel["target"]["toolComponent"]["guid"] == taxonomy["guid"]


def test_notes_are_notifications_not_failures(validator):
    report = scan_report(notes=[PathMessage("/repo/link", "symbolic link to a directory: not followed")])
    invocation = the_run(valid(to_sarif(report), validator))["invocations"][0]
    assert invocation["executionSuccessful"] is True and "exitCode" not in invocation
    (note,) = invocation["toolExecutionNotifications"]
    assert note["level"] == "note" and note["descriptor"] == {"id": sarif.PATH_SKIPPED, "index": 1}
    assert note["message"]["text"] == "Symbolic link to a directory: not followed"


def test_unknown_check_id_still_has_a_descriptor(validator):
    run = the_run(valid(to_sarif(scan_report([finding("future.check", Severity.HIGH)])), validator))
    result = run["results"][0]
    assert run["tool"]["driver"]["rules"][result["ruleIndex"]]["id"] == "future.check/high"


# -- severity sub-rules ----------------------------------------------------------------------------------

def test_a_finding_at_its_rules_usual_severity_uses_the_rule():
    run = the_run(to_sarif(scan_report([finding("values.embedded-file", Severity.CRITICAL)])))
    assert run["results"][0]["ruleId"] == "values.embedded-file"
    assert len(run["tool"]["driver"]["rules"]) == len(rules.RULES)


def test_a_finding_at_another_severity_uses_a_sub_rule(validator):
    # GitHub shows the rule's security severity, so a vendor PDF must not inherit "critical" from executables.
    run = the_run(valid(to_sarif(scan_report([finding("values.embedded-file", Severity.LOW),
                                              finding("values.embedded-file", Severity.LOW, offset=9)])), validator))
    result = run["results"][0]
    descriptor = run["tool"]["driver"]["rules"][result["ruleIndex"]]
    assert result["ruleId"] == descriptor["id"] == "values.embedded-file/low"
    assert descriptor["properties"]["security-severity"] == "2.0"
    assert descriptor["defaultConfiguration"]["level"] == "note"
    assert descriptor["name"] == "ValuesEmbeddedFileLow" and descriptor["shortDescription"]["text"].endswith("(low)")
    assert descriptor["helpUri"] == rules.RULES["values.embedded-file"].help_uri
    assert [d["id"] for d in run["tool"]["driver"]["rules"]].count("values.embedded-file/low") == 1
    assert result["properties"] == {"severity": "low", "offset": 0, "domain": "file"} and result["level"] == "note"


# -- fingerprints ---------------------------------------------------------------------------------------

def fingerprints(report, srcroot="/repo"):
    run = the_run(sarif.to_sarif(report, srcroot, pathmod=posixpath))
    return [r["partialFingerprints"] for r in run["results"]]


def test_fingerprint_is_github_s_key_and_a_versioned_one():
    (fp,) = fingerprints(scan_report([finding()]))
    assert set(fp) == {"primaryLocationLineHash", "radguard/v1"} and fp["radguard/v1"] == fp["primaryLocationLineHash"]
    assert re.fullmatch(r"[0-9a-f]{16}:1", fp["primaryLocationLineHash"])


def test_fingerprint_does_not_depend_on_how_the_path_was_written():
    a = fingerprints(scan_report([finding(path="/repo/sub/a.dcm")]))
    b = fingerprints(scan_report([finding(path="/repo/sub/../sub/./a.dcm")]))
    c = fingerprints(scan_report([finding(path="/elsewhere/sub/a.dcm")]), srcroot="/elsewhere")
    assert a == b == c


@pytest.mark.parametrize("change", [{"offset": 1}, {"check": "preamble.mz-header"}, {"path": "/repo/b.dcm"},
                                    {"offset": None}])
def test_fingerprint_changes_with_rule_file_or_place(change):
    assert fingerprints(scan_report([finding()])) != fingerprints(scan_report([finding(**change)]))


def test_fingerprint_ignores_message_and_severity():
    base = fingerprints(scan_report([finding()]))
    assert fingerprints(scan_report([finding(detail="different words", severity=Severity.LOW)])) == base


def test_repeated_findings_get_distinct_fingerprints():
    fps = [fp["primaryLocationLineHash"] for fp in fingerprints(scan_report([finding(), finding()]))]
    assert fps[0].endswith(":1") and fps[1].endswith(":2") and fps[0][:16] == fps[1][:16]


# -- limits ---------------------------------------------------------------------------------------------

def test_results_beyond_github_s_limit_are_omitted_least_severe_first(validator, monkeypatch):
    monkeypatch.setattr(sarif, "MAX_RESULTS", 2)
    findings = [finding("preamble.pe-polyglot", offset=1), finding("preamble.mz-header", offset=2),
                finding("preamble.nonstandard", offset=3)]  # critical, high, low: already in report order
    run = the_run(valid(to_sarif(scan_report(findings)), validator))
    assert [r["ruleId"] for r in run["results"]] == ["preamble.pe-polyglot", "preamble.mz-header"]
    assert run["properties"]["resultsOmitted"] == 1
    (note,) = run["invocations"][0]["toolExecutionNotifications"]
    assert note["descriptor"]["id"] == sarif.RESULTS_OMITTED and note["level"] == "warning" and "locations" not in note
    assert note["message"]["text"] == "1 least severe results were omitted"


def test_no_results_omitted_at_exactly_the_limit(monkeypatch):
    monkeypatch.setattr(sarif, "MAX_RESULTS", 1)
    run = the_run(to_sarif(scan_report([finding()])))
    assert run["properties"]["resultsOmitted"] == 0 and run["invocations"][0]["toolExecutionNotifications"] == []


# -- attacker-controlled text ---------------------------------------------------------------------------

def unescape(text: str) -> str:
    """What a SARIF viewer that honours the escapes displays."""
    out, i = [], 0
    while i < len(text):
        pair = text[i : i + 2]
        if text[i] == "\\" and len(pair) == 2 and pair[1] in "\\[]<>(":
            out.append(pair[1])
        elif pair in ("{{", "}}"):
            out.append(pair[0])
        else:
            out.append(text[i])
            i += 1
            continue
        i += 2
    return "".join(out)


VS_VIEWER_LINK = re.compile(r"\[(?P<text>[^\]]+)\]\((?P<target>[^)]+)\)")  # Microsoft's SARIF viewer


def assert_inert(message: str) -> None:
    assert not VS_VIEWER_LINK.search(message)
    for match in re.finditer(r"[\[\]<>]", message):  # GFM: only an unescaped bracket can open a link or tag
        backslashes = len(message[: match.start()]) - len(message[: match.start()].rstrip("\\"))
        assert backslashes % 2 == 1, message
    assert "{" not in message.replace("{{", "") and "}" not in message.replace("}}", "")


@pytest.mark.parametrize("hostile", [
    "[Download the fixed viewer](https://evil.example)",
    "\\[x\\](1)",  # escapes written by the attacker
    "a\\](https://evil.example)",
    "<a href='https://evil.example'>click</a>",
    "{0} {1}",
    "trailing backslash \\",
    "x\x1b[2J\u202egpj.exe",
])
def test_hostile_text_cannot_become_markup(hostile):
    message = sarif.message_text("Title", hostile)
    assert_inert(message)
    assert unescape(message) == "Title. " + hostile[:1].upper() + hostile[1:] if hostile.isprintable() else True


@given(st.text(max_size=200), st.text(max_size=200))
def test_any_text_is_made_inert_without_losing_anything(title, detail):
    message = sarif.message_text(title, detail)
    assert_inert(message)
    expected = ". ".join(p[:1].upper() + p[1:] for p in (safe(title), safe(detail)) if p)
    assert unescape(message) == expected
    message.encode("ascii", "backslashreplace").decode("ascii")  # always serialisable


def test_messages_are_capped():
    assert sarif.MAX_MESSAGE == 4096
    message = sarif.message_text("T", "x" * 10_000)
    assert len(unescape(message)) == 4096 and message.endswith("...")


def test_message_cap_boundary():
    exactly = sarif.message_text("7" * 4096)
    assert len(exactly) == 4096 and not exactly.endswith("...")
    assert sarif.message_text("7" * 4097) == "7" * 4093 + "..."


def test_sub_rules_are_ordered_by_rule_then_most_severe_first():
    findings = [finding("values.embedded-file", Severity.LOW, offset=1),
                finding("pixels.slack", Severity.MEDIUM, offset=2),
                finding("values.embedded-file", Severity.HIGH, offset=3)]
    ids = [d["id"] for d in the_run(to_sarif(scan_report(findings)))["tool"]["driver"]["rules"]]
    assert ids[len(rules.RULES):] == ["pixels.slack/medium", "values.embedded-file/high", "values.embedded-file/low"]


def test_first_sentence_is_the_title():
    assert sarif.message_text("Two images in one file", "2 Pixel Data elements") == \
        "Two images in one file. 2 Pixel Data elements"


# -- paths to URIs ----------------------------------------------------------------------------------------

@pytest.mark.parametrize("path,expected", [
    ("/repo/a b.dcm", {"uri": "a%20b.dcm", "uriBaseId": "%SRCROOT%"}),
    ("/repo/javascript:alert(1)", {"uri": "javascript%3Aalert%281%29", "uriBaseId": "%SRCROOT%"}),  # no scheme
    ("/repo/100%.dcm", {"uri": "100%25.dcm", "uriBaseId": "%SRCROOT%"}),  # a bare % crashed Trivy's writer
    ("/repo/q?#x.dcm", {"uri": "q%3F%23x.dcm", "uriBaseId": "%SRCROOT%"}),
    ("/repo/back\\slash.dcm", {"uri": "back%5Cslash.dcm", "uriBaseId": "%SRCROOT%"}),  # a name character on POSIX
    ("/repo/..x/a.dcm", {"uri": "..x/a.dcm", "uriBaseId": "%SRCROOT%"}),
    ("/repo/../etc/x.dcm", {"uri": "file:///etc/x.dcm"}),  # outside the root: absolute
    ("/elsewhere/x.dcm", {"uri": "file:///elsewhere/x.dcm"}),
    ("/repo", {"uri": "file:///repo"}),
    ("/repo/caf\u00e9.dcm", {"uri": "caf%C3%A9.dcm", "uriBaseId": "%SRCROOT%"}),
    ("/repo/x\udcffy.dcm", {"uri": "x%FFy.dcm", "uriBaseId": "%SRCROOT%"}),  # the original byte, not U+DCFF
    ("/repo/x\ud800y.dcm", {"uri": "x%ED%A0%80y.dcm", "uriBaseId": "%SRCROOT%"}),
])
def test_posix_paths(path, expected):
    assert sarif.artifact_location(path, "/repo", posixpath) == expected


@pytest.mark.parametrize("path,root,expected", [
    ("C:\\repo\\d\\a b.dcm", "C:\\repo", {"uri": "d/a%20b.dcm", "uriBaseId": "%SRCROOT%"}),
    ("D:\\scans\\x.dcm", "C:\\repo", {"uri": "file:///D:/scans/x.dcm"}),  # another drive
    ("\\\\server\\share\\d\\x.dcm", "C:\\repo", {"uri": "file://server/share/d/x.dcm"}),
    ("\\\\?\\D:\\scans\\x.dcm", "C:\\repo", {"uri": "file:///D:/scans/x.dcm"}),
    ("\\\\?\\UNC\\server\\share\\x.dcm", "C:\\repo", {"uri": "file://server/share/x.dcm"}),
    ("C:\\repo\\x\udcffy.dcm", "C:\\repo", {"uri": "x%ED%B3%BFy.dcm", "uriBaseId": "%SRCROOT%"}),  # WTF-8
])
def test_windows_paths(path, root, expected):
    assert sarif.artifact_location(path, root, ntpath) == expected


# Hostile characters on purpose: URI delimiters, and surrogates (Hypothesis excludes them by default), both the
# surrogateescape range that stands for undecodable POSIX bytes and the rest.
HOSTILE = st.sampled_from([*"%:#?[]\\ .~", "\udc80", "\udcff", "\ud800", "\udfff", "\u00e9", "\u60a3"])


def names(excluded: str):
    chars = st.one_of(st.characters(exclude_categories=(), exclude_characters=excluded),
                      HOSTILE.filter(lambda c: c not in excluded))
    return st.text(chars, min_size=1, max_size=12)


NAME = names("/\x00").filter(lambda n: n not in (".", ".."))


@given(st.lists(NAME, min_size=1, max_size=4))
def test_posix_uris_round_trip_to_the_exact_bytes(parts):
    path = "/repo/" + "/".join(parts)
    loc = sarif.artifact_location(path, "/repo", posixpath)
    assert loc["uriBaseId"] == "%SRCROOT%" and URI_CHARS.fullmatch(loc["uri"]) and not loc["uri"].startswith("/")
    raw = "/".join(parts).encode("utf-8", "surrogateescape" if all(
        not 0xD800 <= ord(c) <= 0xDFFF or 0xDC80 <= ord(c) <= 0xDCFF for c in "".join(parts)) else "surrogatepass")
    assert unquote_to_bytes(loc["uri"]) == raw


RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{n}" for n in range(10)), *(f"LPT{n}" for n in range(10))}
WINDOWS_NAME = names('\\/:*?"<>|\x00').filter(
    lambda n: n.rstrip(". ") == n and n.split(".")[0].upper().rstrip() not in RESERVED)


@given(st.lists(WINDOWS_NAME, min_size=1, max_size=4))
def test_windows_uris_round_trip(parts):
    loc = sarif.artifact_location("C:\\repo\\" + "\\".join(parts), "C:\\repo", ntpath)
    assert loc["uriBaseId"] == "%SRCROOT%" and URI_CHARS.fullmatch(loc["uri"])
    assert unquote_to_bytes(loc["uri"]) == wtf8("/".join(parts))


def wtf8(name: str) -> bytes:
    """The bytes of an NTFS name: its UTF-16 code units (surrogates paired as Windows pairs them) in WTF-8."""
    return name.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "surrogatepass").encode(
        "utf-8", "surrogatepass")


def test_a_surrogate_pair_is_one_character_on_ntfs():
    # Python strings can hold a valid pair as two code points; Windows' own path functions merge it, so the URI
    # must not depend on whether the path went through them.
    split, merged = "C:\\repo\\\ud800\udc80.dcm", "C:\\repo\\\U00010080.dcm"
    uri = sarif.artifact_location(split, "C:\\repo", ntpath)["uri"]
    assert uri == sarif.artifact_location(merged, "C:\\repo", ntpath)["uri"] == "%F0%90%82%80.dcm"
    assert sarif.artifact_location("C:\\repo\\\udc80\ud800.dcm", "C:\\repo", ntpath)["uri"] == \
        "%ED%B2%80%ED%A0%80.dcm"  # reversed: not a pair, so both stay unpaired surrogates
