"""Write a SARIF log that exercises every branch of the SARIF writer, for external validators.

The scan of examples/ covers the common case. This log adds what a real scan of the examples never
produces: an incomplete scan (error notification), a skipped path (note), a finding under a severity
sub-rule, an offset into a deflated dataset, a finding about a whole file, hostile text and file names,
and results omitted at the size limit. CI validates both logs with Microsoft's SARIF Multitool.

    python scripts/sarif_edge_cases.py edge-cases.sarif
"""

from __future__ import annotations

import posixpath
import sys
from datetime import datetime, timezone
from unittest import mock

from radguard import sarif
from radguard.findings import INFLATED, Finding, Severity
from radguard.output import dumps
from radguard.report import Artifact, PathMessage, ScanReport

WHEN = datetime(2026, 10, 9, tzinfo=timezone.utc)


def edge_report() -> ScanReport:
    files = {"/repo/a b.dcm": Artifact("/repo/a b.dcm", 40_000, "ab" * 32),
             "/repo/javascript:x.dcm": Artifact("/repo/javascript:x.dcm", 512, "cd" * 32)}
    findings = [
        Finding("preamble.pe-polyglot", Severity.CRITICAL, "Windows executable in the preamble", "details",
                "/repo/javascript:x.dcm", 0x196),
        Finding("structure.nonzero-padding", Severity.HIGH, "Data hidden in trailing padding", "details",
                "/repo/a b.dcm", 0x9000, domain=INFLATED),
        Finding("values.embedded-file", Severity.LOW, "PDF document inside an attribute value",
                "[Download the fixed viewer](https://evil.example) <b>{0}</b>", "/repo/a b.dcm", 0x200),
        Finding("scan.findings-suppressed", Severity.MEDIUM, "Finding flood suppressed", "details",
                "/repo/a b.dcm"),
        Finding("preamble.nonstandard", Severity.LOW, "Unrecognised non-zero preamble", "omitted at the limit",
                "/repo/a b.dcm", 0),
    ]
    return ScanReport(WHEN, WHEN, findings, [PathMessage("/repo/gone.dcm", "No such file or directory")],
                      [PathMessage("/repo/link", "symbolic link to a directory: not followed")], files,
                      files=3, dicom=2, skipped=0)


def main(path: str) -> None:
    with mock.patch.object(sarif, "MAX_RESULTS", 4):  # the fifth finding is omitted and reported as such
        log = sarif.to_sarif(edge_report(), "/repo", exit_code=3, pathmod=posixpath)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(dumps(log))


if __name__ == "__main__":
    main(sys.argv[1])
