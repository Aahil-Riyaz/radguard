"""SARIF 2.1.0 output, for GitHub code scanning and any other SARIF consumer.

Design and sources: docs/design/sarif.md. In short:

* Locations are binary regions. DICOM files are not text, and SARIF 3.30.1
  forbids line numbers in binary artifacts, so a finding's place is
  region.byteOffset, and a finding about a whole file has no region.
* GitHub cannot fingerprint a result without a line number, so every result
  carries its own: the rule, the file and the offset, hashed.
* GitHub takes an alert's displayed severity from its rule, never from the
  result. A finding more or less severe than its rule's usual severity is
  therefore reported under a sub-rule, "<rule>/<severity>", so a vendor PDF
  in a private tag is not shown as a critical alert.
* Text that came from a scanned file is attacker-controlled. Messages are made
  inert (no control or bidi characters, no link or HTML syntax, no SARIF
  placeholders), and paths become URIs by percent-encoding their bytes, so a
  hostile file name can neither create a link nor invalidate the log.
* An incomplete scan says so: executionSuccessful is false and every path
  that was not examined is an error notification.
"""

from __future__ import annotations

import hashlib
import ntpath
import os
import uuid
from collections import Counter
from types import ModuleType
from urllib.parse import quote_from_bytes

from radguard import __url__, __version__, rules
from radguard.findings import FILE, Finding, Severity
from radguard.output import safe
from radguard.report import ScanReport, timestamp

SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
SRCROOT = "%SRCROOT%"
FINGERPRINT = "radguard/v1"  # change the version whenever the fingerprint's inputs change
GITHUB_FINGERPRINT = "primaryLocationLineHash"  # the only key GitHub code scanning tracks alerts by
MIME_TYPE = "application/dicom"  # IANA-registered (RFC 3240)
MAX_RESULTS = 25_000  # GitHub rejects a run with more; the most severe results are kept
MAX_MESSAGE = 4096  # characters of display text per message, before escaping
SRCROOT_DESCRIPTION = ("The directory RadGuard was run from. Relative URIs resolve against it; for GitHub code "
                       "scanning, run RadGuard from the repository root.")

LEVELS = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
          Severity.LOW: "note", Severity.INFO: "note"}
# GitHub's bands: above 9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low; 0.0 means none.
SECURITY_SEVERITY = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5",
                     Severity.LOW: "2.0", Severity.INFO: "0.0"}

CWE_TAXONOMY = "CWE"
CWE_GUID = str(uuid.uuid5(uuid.NAMESPACE_URL, "https://cwe.mitre.org/"))  # stable across runs and versions

# Notification descriptors: why a path is missing from the results.
PATH_ERROR, PATH_SKIPPED, RESULTS_OMITTED = "scan.path-error", "scan.path-skipped", "sarif.results-omitted"
NOTIFICATIONS = (  # id, level, short description, full description, what to do
    (PATH_ERROR, "error", "A path could not be examined",
     "A file or directory could not be read, or a check failed on it. The scan is incomplete: the absence of "
     "results for this path is not evidence that it is clean.",
     "Fix the cause given in the message (permissions, a file that changed or disappeared, a Git LFS pointer) and "
     "scan again. Until then, treat the path as not scanned."),
    (PATH_SKIPPED, "note", "A path was deliberately not examined",
     "For example a symbolic link to a directory, which is not followed.",
     "If the target should be covered, scan it directly."),
    (RESULTS_OMITTED, "warning", "Least severe results omitted",
     f"GitHub code scanning rejects a run with more than {MAX_RESULTS:,} results, so the most severe ones were "
     "kept. The JSON report lists every finding.",
     "Use the JSON report (--format json) for the complete list, or scan fewer files per run."),
)


def to_sarif(report: ScanReport, srcroot: str, exit_code: int | None = None,
             pathmod: ModuleType = os.path) -> dict[str, object]:
    """The SARIF log for `report`. Paths under `srcroot` become relative to %SRCROOT%, which is what
    GitHub expects when `srcroot` is the repository root."""
    findings = report.findings[:MAX_RESULTS]  # already most severe first
    omitted = len(report.findings) - len(findings)

    catalog = sorted(rules.RULES.values(), key=lambda r: r.id)
    catalog += [rules.rule(i) for i in sorted({f.check for f in findings} - rules.RULES.keys())]  # never fatal
    variants = sorted({(f.check, f.severity) for f in findings if f.severity != rules.rule(f.check).severity},
                      key=lambda v: (v[0], -v[1]))
    descriptors = [_descriptor(r) for r in catalog] + [_descriptor(rules.rule(c), s) for c, s in variants]
    rule_index = {d["id"]: n for n, d in enumerate(descriptors)}

    artifacts = sorted(report.artifacts.values(), key=lambda a: a.path)
    artifact_index = {a.path: n for n, a in enumerate(artifacts)}

    def location(path: str) -> dict[str, object]:
        loc = artifact_location(path, srcroot, pathmod)
        if path in artifact_index:
            loc["index"] = artifact_index[path]
        return loc

    seen: Counter[str] = Counter()
    results = []
    for f in findings:
        loc = location(f.path)
        rule_id = rule_identifier(f)
        digest = fingerprint(f.check, str(loc["uri"]), f.offset, f.domain)
        seen[digest] += 1  # the same rule twice at one place: keep the alerts apart, as CodeQL does
        size = report.artifacts[f.path].size if f.path in report.artifacts else None
        results.append(_result(f, rule_id, rule_index[rule_id], loc, size, f"{digest}:{seen[digest]}"))

    notifications = [_notification(PATH_ERROR, e.message, location(e.path)) for e in report.errors]
    notifications += [_notification(PATH_SKIPPED, n.message, location(n.path)) for n in report.notes]
    if omitted:
        notifications.append(_notification(RESULTS_OMITTED, f"{omitted:,} least severe results were omitted"))

    invocation: dict[str, object] = {
        "executionSuccessful": report.complete,
        "startTimeUtc": timestamp(report.started),
        "endTimeUtc": timestamp(report.finished),
        "toolExecutionNotifications": notifications,
    }
    if exit_code is not None:
        invocation["exitCode"] = exit_code

    run: dict[str, object] = {
        "tool": {"driver": {
            "name": "RadGuard",
            "semanticVersion": __version__,
            "informationUri": __url__,
            "rules": descriptors,
            "notifications": [{"id": i, "name": rules.pascal_case(i), "shortDescription": {"text": short},
                               "fullDescription": {"text": full}, "help": {"text": advice},
                               "defaultConfiguration": {"level": level}}
                              for i, level, short, full, advice in NOTIFICATIONS],
            "supportedTaxonomies": [{"name": CWE_TAXONOMY, "guid": CWE_GUID}],
        }},
        "invocations": [invocation],
        # The base is deliberately left unresolved (SARIF 3.14.14 allows it): an absolute path names the
        # scanning machine's user and directories, and DICOM directory names often carry patient identifiers.
        "originalUriBaseIds": {SRCROOT: {"description": {"text": SRCROOT_DESCRIPTION}}},
        "artifacts": [{
            "location": artifact_location(a.path, srcroot, pathmod),
            "length": a.size,
            "mimeType": MIME_TYPE,
            "hashes": {"sha-256": a.sha256},
            "roles": ["analysisTarget"],
        } for a in artifacts],
        "taxonomies": [_cwe_taxonomy()],
        "results": results,
        "properties": {"files": report.files, "dicom": report.dicom, "skipped": report.skipped,
                       "complete": report.complete, "resultsOmitted": omitted},
    }
    return {"$schema": SCHEMA, "version": "2.1.0", "runs": [run]}


def rule_identifier(finding: Finding) -> str:
    """The SARIF rule a finding is reported under: its own rule, or the sub-rule for its severity."""
    if finding.severity == rules.rule(finding.check).severity:
        return finding.check
    return f"{finding.check}/{finding.severity}"


def _descriptor(rule: rules.Rule, severity: Severity | None = None) -> dict[str, object]:
    rule_id, name, title = rule.id, rule.name, rule.title
    if severity is not None:  # a severity variant of `rule`
        rule_id, name, title = f"{rule.id}/{severity}", f"{rule.name}{str(severity).capitalize()}", \
            f"{rule.title} ({severity})"
    severity = rule.severity if severity is None else severity
    references = "".join(f"\n- <{url}>" for url in rule.references)
    descriptor: dict[str, object] = {
        "id": rule_id,
        "name": name,
        "shortDescription": {"text": title},
        "fullDescription": {"text": rule.description},
        "help": {"text": rule.advice,
                 "markdown": f"{rule.description}\n\n**What to do:** {rule.advice}"
                             + (f"\n\n**References:**{references}" if references else "")},
        "helpUri": rule.help_uri,
        "defaultConfiguration": {"level": LEVELS[severity]},
        "properties": {
            "tags": list(rule.tags),
            "precision": rule.precision,
            "security-severity": SECURITY_SEVERITY[severity],
        },
    }
    if rule.cwe:
        descriptor["relationships"] = [
            {"target": {"id": str(n), "toolComponent": {"name": CWE_TAXONOMY, "guid": CWE_GUID}},
             "kinds": ["relevant"]} for n in rule.cwe]
    return descriptor


def _cwe_taxonomy() -> dict[str, object]:
    return {
        "name": CWE_TAXONOMY,
        "organization": "MITRE",
        "guid": CWE_GUID,
        "informationUri": "https://cwe.mitre.org/",
        "shortDescription": {"text": "The MITRE Common Weakness Enumeration"},
        "isComprehensive": False,
        "taxa": [{"id": str(n), "name": rules.CWE_NAMES[n], "shortDescription": {"text": rules.CWE_NAMES[n]},
                  "helpUri": rules.cwe_uri(n)} for n in sorted(rules.CWE_NAMES)],
    }


def _result(finding: Finding, rule_id: str, rule_index: int, location: dict[str, object], size: int | None,
            fingerprint_value: str) -> dict[str, object]:
    physical: dict[str, object] = {"artifactLocation": location}
    properties: dict[str, object] = {"severity": str(finding.severity)}
    where = ""
    if finding.offset is not None:
        properties.update(offset=finding.offset, domain=finding.domain)
        where = (f"At byte {finding.offset:#x} of the file" if finding.domain == FILE
                 else f"At byte {finding.offset:#x} of the decompressed dataset (the file is deflated)")
    if finding.offset is not None and finding.domain == FILE:
        physical["region"] = {"byteOffset": finding.offset}
    elif size is not None:
        # About the whole file, or about a position in the decompressed dataset, which is no position in the
        # file: the region is the whole file, stated explicitly rather than left to the spec's default.
        physical["region"] = {"byteOffset": 0, "byteLength": size}
    # The offset is in the text too (SARIF 3.27.11): GitHub shows the file of a binary region but not the offset.
    return {
        "ruleId": rule_id,
        "ruleIndex": rule_index,
        "level": LEVELS[finding.severity],
        "message": {"text": message_text(finding.title, finding.detail, where)},
        "locations": [{"physicalLocation": physical}],
        "partialFingerprints": {FINGERPRINT: fingerprint_value, GITHUB_FINGERPRINT: fingerprint_value},
        "properties": properties,
    }


def _notification(descriptor: str, text: str, location: dict[str, object] | None = None) -> dict[str, object]:
    index = next(n for n, (i, *_) in enumerate(NOTIFICATIONS) if i == descriptor)
    notification: dict[str, object] = {
        "descriptor": {"id": descriptor, "index": index},
        "level": NOTIFICATIONS[index][1],
        "message": {"text": message_text(text)},
    }
    if location is not None:
        notification["locations"] = [{"physicalLocation": {"artifactLocation": location}}]
    return notification


def fingerprint(check: str, uri: str, offset: int | None, domain: str = FILE) -> str:
    """Identity of a finding across runs: the same rule at the same place in the same file. It uses the URI
    rather than the path as scanned, so it does not depend on where the scan was started from."""
    key = "\0".join((check, uri, "-" if offset is None else f"{domain}:{offset}"))
    return hashlib.sha256(key.encode("ascii")).hexdigest()[:16]


# -- making attacker-controlled text inert ----------------------------------------------------------

# Backslash first, so an attacker's own backslash cannot cancel one of ours.
_ESCAPES = str.maketrans({"\\": "\\\\", "[": "\\[", "]": "\\]", "<": "\\<", ">": "\\>", "{": "{{", "}": "}}"})


def message_text(*parts: str) -> str:
    """A SARIF message from tool-written `parts` that may embed attacker-controlled text.

    * output.safe() removes control, bidi and invisible characters.
    * "[", "]" and "\\" are backslash-escaped (SARIF 3.11.6), and ( after ] gets one too, so no viewer finds
      "[text](target)", which SARIF viewers render as a link. Microsoft's viewer matches links even
      when the brackets are escaped; GitHub may render messages as Markdown.
    * "<" and ">" are escaped: SARIF producers must not emit HTML (3.11.4.2).
    * "{" and "}" are doubled: single braces are argument placeholders (3.11.5).

    The first part becomes the first sentence, the one GitHub shows when space is short.
    """
    text = ". ".join(_sentence(safe(p)) for p in parts if p)
    if len(text) > MAX_MESSAGE:
        text = text[: MAX_MESSAGE - 3] + "..."
    return text.translate(_ESCAPES).replace("\\](", "\\]\\(")


def _sentence(text: str) -> str:
    return text[:1].upper() + text[1:]


# -- paths to URIs ------------------------------------------------------------------------------

def artifact_location(path: str, srcroot: str, pathmod: ModuleType = os.path) -> dict[str, object]:
    """A path under `srcroot` becomes a reference relative to %SRCROOT%; anything else a file: URI."""
    absolute, root = pathmod.abspath(path), pathmod.abspath(srcroot)
    try:
        relative = pathmod.relpath(absolute, root)
    except ValueError:  # Windows: a different drive has no relative path
        relative = None
    if relative is not None and relative != pathmod.curdir and not _escapes(relative, pathmod):
        return {"uri": _quote(relative, pathmod), "uriBaseId": SRCROOT}
    return {"uri": file_uri(absolute, pathmod)}


def file_uri(absolute: str, pathmod: ModuleType = os.path) -> str:
    windows = pathmod is ntpath
    if windows:
        absolute = _strip_extended_prefix(absolute)
    drive, rest = pathmod.splitdrive(absolute)
    rest_uri = _quote(rest, pathmod)
    if windows and drive[:2] in ("\\\\", "//"):  # UNC \\server\share: the server is the URI's host
        host, _, share = drive[2:].replace("\\", "/").partition("/")
        return f"file://{_quote(host, pathmod)}/{_quote(share, pathmod)}{rest_uri}"
    if drive:  # C:
        return f"file:///{drive}{rest_uri}"
    return f"file://{rest_uri}"


def _strip_extended_prefix(path: str) -> str:
    # \\?\C:\x is C:\x; \\?\UNC\server\share is \\server\share.
    if path.startswith("\\\\?\\UNC\\"):
        return "\\\\" + path[8:]
    if path.startswith("\\\\?\\"):
        return path[4:]
    return path


def _escapes(relative: str, pathmod: ModuleType) -> bool:
    return pathmod.isabs(relative) or relative == pathmod.pardir or relative.startswith(pathmod.pardir + pathmod.sep)


def _quote(path: str, pathmod: ModuleType) -> str:
    """Percent-encode a path's bytes, keeping only unreserved characters and "/".

    ":" is always encoded, so no segment can be read as a URI scheme. The bytes are the name as the file
    system stores it. On POSIX, names that are not UTF-8 reach Python as surrogateescape code points and turn
    back into their original bytes. NTFS names are UTF-16: the name is re-read as UTF-16 code units, which
    pairs surrogates the way Windows does (a string can hold a pair as two code points; the file system
    cannot), and written as WTF-8, so an unpaired surrogate survives too. The URI is then the same whichever
    platform builds it.
    """
    if pathmod is ntpath:
        units = path.replace("\\", "/").encode("utf-16-le", "surrogatepass")
        return quote_from_bytes(units.decode("utf-16-le", "surrogatepass").encode("utf-8", "surrogatepass"),
                                safe="/")
    try:
        raw = path.encode("utf-8", "surrogateescape")
    except UnicodeEncodeError:  # a surrogate that no POSIX byte decodes to; keep it rather than fail
        raw = path.encode("utf-8", "surrogatepass")
    return quote_from_bytes(raw, safe="/")
