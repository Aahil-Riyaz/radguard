"""Command-line entry point: `radguard scan <paths...>`."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter

from radguard import __version__
from radguard.findings import Severity
from radguard.scanner import scan_paths

SEVERITY_NAMES = [str(s) for s in Severity]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="radguard",
        description="Integrity and safety scanner for medical imaging (DICOM).",
    )
    parser.add_argument("--version", action="version", version=f"radguard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan DICOM files and directories")
    scan.add_argument("paths", nargs="+", help="files or directories (searched recursively)")
    scan.add_argument("--format", choices=("text", "json"), default="text")
    scan.add_argument(
        "--fail-on", choices=SEVERITY_NAMES, default="high",
        help="exit with status 1 if any finding is at least this severe (default: high)",
    )

    args = parser.parse_args(argv)
    return _scan(args)


def _scan(args: argparse.Namespace) -> int:
    threshold = Severity.parse(args.fail_on)
    findings, errors = [], []
    files = dicom = 0

    for result in scan_paths(args.paths):
        files += 1
        dicom += result.is_dicom
        findings.extend(result.findings)
        if result.error:
            errors.append({"path": result.path, "error": result.error})

    findings.sort(key=lambda f: (-f.severity, f.path))
    by_severity = Counter(str(f.severity) for f in findings)
    summary = {
        "files": files,
        "dicom": dicom,
        "skipped": files - dicom - len(errors),
        "errors": len(errors),
        "findings": {name: by_severity.get(name, 0) for name in reversed(SEVERITY_NAMES)},
    }

    if args.format == "json":
        json.dump(
            {"summary": summary, "findings": [f.to_dict() for f in findings], "errors": errors},
            sys.stdout, indent=2,
        )
        sys.stdout.write("\n")
    else:
        for f in findings:
            print(f"{str(f.severity).upper():<9} {f.check:<26} {f.path}")
            print(f"{'':<9} {f.title}")
            print(f"{'':<9} {f.detail}")
        for e in errors:
            print(f"{'ERROR':<9} {e['path']}: {e['error']}", file=sys.stderr)
        counts = ", ".join(f"{n}={c}" for n, c in summary["findings"].items() if c)
        print(
            f"\nscanned {files} files: {dicom} DICOM, {summary['skipped']} skipped, "
            f"{len(errors)} errors; findings: {counts or 'none'}"
        )

    return 1 if any(f.severity >= threshold for f in findings) else 0
