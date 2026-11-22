"""SARIF 2.1.0 output, so findings show up in GitHub code scanning and SIEMs.

Design notes
- One SARIF *rule* per check id (e.g. "preamble.pe-polyglot"); one *result* per finding.
- GitHub ranks alerts by the `security-severity` rule property (a CVSS-like 0-10
  score) and falls back to `level` otherwise, so both are set.
- Artifact URIs are relative to the working directory when possible, because code
  scanning only attaches an alert to a file when the URI is repo-relative. Paths
  outside the working directory fall back to absolute `file:` URIs.
- DICOM files are binary: there are no meaningful line numbers. Every region is
  anchored at line 1 (GitHub requires one) and the real position is carried in
  `byteOffset`, which SARIF-aware tools can use.
- A scan that could not examine every path is reported through
  `invocations[].toolExecutionNotifications` with `executionSuccessful: false`,
  mirroring exit status 3 of the CLI, so a consumer never mistakes partial
  coverage for a clean bill of health.
- Output is produced by json.dumps, which escapes control characters and (with
  ensure_ascii) every non-ASCII code point, so attacker-controlled file names
  and values cannot smuggle terminal escapes into downstream viewers.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath

from radguard import __version__
from radguard.findings import Finding, Severity

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/Aahil-Riyaz/radguard"

_LEVEL = {
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}

# GitHub buckets security-severity as: >9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low.
_SECURITY_SEVERITY = {
    Severity.INFO: "0.5",
    Severity.LOW: "3.0",
    Severity.MEDIUM: "5.5",
    Severity.HIGH: "8.0",
    Severity.CRITICAL: "9.5",
}


def artifact_uri(path: str, base: Path | None = None) -> str:
    """Repo-relative POSIX URI for `path`, or an absolute file: URI if it lies outside `base`."""
    base = (base or Path.cwd()).resolve()
    resolved = Path(path).resolve()
    try:
        return PurePosixPath(resolved.relative_to(base).as_posix()).as_posix()
    except ValueError:
        return resolved.as_uri()


def _rule(finding: Finding) -> dict[str, object]:
    # Several findings share a rule id; the first one seen supplies the rule text.
    rule: dict[str, object] = {
        "id": finding.check,
        "name": "".join(part.capitalize() for part in finding.check.replace(".", "-").split("-")),
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.detail},
        "defaultConfiguration": {"level": _LEVEL[finding.severity]},
        "properties": {
            "security-severity": _SECURITY_SEVERITY[finding.severity],
            "tags": ["security", "dicom", finding.check.split(".", 1)[0]],
        },
    }
    if finding.references:
        rule["helpUri"] = finding.references[0]
    return rule


def _location(path: str, base: Path | None, region: dict[str, object] | None = None) -> dict[str, object]:
    physical: dict[str, object] = {"artifactLocation": {"uri": artifact_uri(path, base)}}
    if region is not None:
        physical["region"] = region
    return {"physicalLocation": physical}


def _result(finding: Finding, rule_index: int, base: Path | None) -> dict[str, object]:
    region: dict[str, object] = {"startLine": 1}
    if finding.offset is not None:
        region["byteOffset"] = finding.offset
    properties: dict[str, object] = {"security-severity": _SECURITY_SEVERITY[finding.severity]}
    if finding.references:
        properties["references"] = list(finding.references)
    return {
        "ruleId": finding.check,
        "ruleIndex": rule_index,
        "level": _LEVEL[finding.severity],
        "message": {"text": f"{finding.title}. {finding.detail}"},
        "locations": [_location(finding.path, base, region)],
        "properties": properties,
    }


def build_sarif(
    findings: list[Finding],
    errors: list[dict[str, str]],
    notes: list[dict[str, str]],
    *,
    base: Path | None = None,
) -> dict[str, object]:
    """Build a SARIF log from scan output. `findings` should already be sorted."""
    rules: list[dict[str, object]] = []
    index: dict[str, int] = {}
    for f in findings:
        if f.check not in index:
            index[f.check] = len(rules)
            rules.append(_rule(f))

    notifications: list[dict[str, object]] = []
    for e in errors:
        notifications.append({
            "level": "error",
            "message": {"text": f"{e['path']}: {e['error']}"},
            "locations": [_location(e["path"], base)],
        })
    for n in notes:
        notifications.append({
            "level": "note",
            "message": {"text": f"{n['path']}: {n['note']}"},
            "locations": [_location(n["path"], base)],
        })

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {
                "name": "radguard",
                "version": __version__,
                "semanticVersion": __version__,
                "informationUri": INFORMATION_URI,
                "rules": rules,
            }},
            "results": [_result(f, index[f.check], base) for f in findings],
            "invocations": [{
                "executionSuccessful": not errors,
                "toolExecutionNotifications": notifications,
            }],
        }],
    }
