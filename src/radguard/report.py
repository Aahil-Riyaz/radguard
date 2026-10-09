"""One scan's results, gathered once and rendered as text or JSON (SARIF: radguard.sarif).

Renderers decide nothing. Completeness, counts and the order of findings all
come from the ScanReport, so every output format tells the same story as the
exit status.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from radguard import __version__
from radguard.findings import Finding, Severity
from radguard.output import safe
from radguard.scanner import FileResult

JSON_SCHEMA_VERSION = 1
SEVERITY_NAMES = [str(s) for s in Severity]


@dataclass(frozen=True)
class Artifact:
    """A file the report says something about, identified by exactly the bytes that were examined."""
    path: str
    size: int
    sha256: str


@dataclass(frozen=True)
class PathMessage:
    path: str
    message: str


@dataclass
class ScanReport:
    started: datetime
    finished: datetime
    findings: list[Finding] = field(default_factory=list)  # most severe first
    errors: list[PathMessage] = field(default_factory=list)  # paths that could not be (fully) examined
    notes: list[PathMessage] = field(default_factory=list)  # paths deliberately not examined
    artifacts: dict[str, Artifact] = field(default_factory=dict)  # by path
    files: int = 0
    dicom: int = 0
    skipped: int = 0

    @property
    def complete(self) -> bool:
        return not self.errors

    def counts(self) -> dict[str, int]:
        """Findings per severity, most severe first, including zeros."""
        found = Counter(str(f.severity) for f in self.findings)
        return {name: found.get(name, 0) for name in reversed(SEVERITY_NAMES)}

    def reaches(self, threshold: Severity) -> bool:
        return any(f.severity >= threshold for f in self.findings)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def collect(results: Iterable[FileResult], clock: Callable[[], datetime] = utc_now) -> ScanReport:
    report = ScanReport(started=clock(), finished=clock())
    for result in results:
        if result.note:
            report.notes.append(PathMessage(result.path, result.note))
            continue
        report.files += 1
        report.dicom += result.is_dicom
        report.skipped += not result.is_dicom and not result.error
        report.findings.extend(result.findings)
        if result.error:
            report.errors.append(PathMessage(result.path, result.error))
        if result.sha256 is not None and result.size is not None:
            report.artifacts[result.path] = Artifact(result.path, result.size, result.sha256)
    # Most severe first; within a file, findings about the whole file before those at an offset.
    report.findings.sort(key=lambda f: (-f.severity, f.path, f.offset is not None, f.offset or 0))
    report.finished = clock()
    return report


def to_json(report: ScanReport) -> dict[str, object]:
    return {
        "tool": {"name": "radguard", "version": __version__},
        "schema_version": JSON_SCHEMA_VERSION,
        "started": timestamp(report.started),
        "finished": timestamp(report.finished),
        "summary": {"files": report.files, "dicom": report.dicom, "skipped": report.skipped,
                    "errors": len(report.errors), "notes": len(report.notes), "complete": report.complete,
                    "findings": report.counts()},
        "findings": [f.to_dict() for f in report.findings],
        "errors": [{"path": e.path, "error": e.message} for e in report.errors],
        "notes": [{"path": n.path, "note": n.message} for n in report.notes],
        "artifacts": [{"path": a.path, "size": a.size, "sha256": a.sha256}
                      for a in sorted(report.artifacts.values(), key=lambda a: a.path)],
    }


def to_text(report: ScanReport) -> list[str]:
    """The human-readable report. Paths and details carry attacker-controlled text, so every line goes
    through safe()."""
    out: list[str] = []
    for f in report.findings:
        out += [safe(f"{str(f.severity).upper():<9} {f.check:<34} {f.path}"),
                safe(f"{'':<9} {f.title}"),
                safe(f"{'':<9} {f.detail}")]
    found = ", ".join(f"{name}={count}" for name, count in report.counts().items() if count)
    notes = f", {len(report.notes)} notes" if report.notes else ""
    return out + ["", f"scanned {report.files} files: {report.dicom} DICOM, {report.skipped} skipped, "
                      f"{len(report.errors)} errors{notes}; findings: {found or 'none'}"]


def diagnostics(report: ScanReport) -> list[str]:
    """Errors and notes for standard error, whatever the report format."""
    lines = [safe(f"{'ERROR':<9} {e.path}: {e.message}") for e in report.errors]
    lines += [safe(f"{'NOTE':<9} {n.path}: {n.message}") for n in report.notes]
    if not report.complete:
        lines.append("scan INCOMPLETE: some paths could not be examined (exit status 3)")
    return lines


def timestamp(moment: datetime) -> str:
    """ISO 8601 in UTC with millisecond precision, as SARIF requires: 2026-10-08T09:30:00.123Z."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"
