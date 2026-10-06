"""Command-line entry point: `radguard scan <paths...>` and `radguard map <file>`."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter

from radguard import __version__, mapview
from radguard.output import safe
from radguard.findings import Severity
from radguard.scanner import open_dicom, scan_paths

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

    mp = sub.add_parser("map", help="show the byte-level structure of one DICOM file")
    mp.add_argument("path")
    mp.add_argument("--depth", type=int, help="hide elements nested deeper than this many sequences")
    mp.add_argument("--show-phi", action="store_true", help="show patient-identifying values instead of masking them")

    args = parser.parse_args(argv)
    return _map(args) if args.command == "map" else _scan(args)


def _scan(args: argparse.Namespace) -> int:
    threshold = Severity.parse(args.fail_on)
    findings, errors = [], []
    files = dicom = skipped = 0

    for result in scan_paths(args.paths):
        files += 1
        dicom += result.is_dicom
        skipped += not result.is_dicom and not result.error
        findings.extend(result.findings)
        if result.error:
            errors.append({"path": result.path, "error": result.error})

    findings.sort(key=lambda f: (-f.severity, f.path, f.offset or 0))
    by_severity = Counter(str(f.severity) for f in findings)
    summary = {
        "files": files,
        "dicom": dicom,
        "skipped": skipped,
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
        # Paths and details carry attacker-controlled text: everything printed goes through safe().
        for f in findings:
            print(safe(f"{str(f.severity).upper():<9} {f.check:<34} {f.path}"))
            print(safe(f"{'':<9} {f.title}"))
            print(safe(f"{'':<9} {f.detail}"))
        for e in errors:
            print(safe(f"{'ERROR':<9} {e['path']}: {e['error']}"), file=sys.stderr)
        counts = ", ".join(f"{n}={c}" for n, c in summary["findings"].items() if c)
        print(
            f"\nscanned {files} files: {dicom} DICOM, {skipped} skipped, "
            f"{len(errors)} errors; findings: {counts or 'none'}"
        )

    return 1 if any(f.severity >= threshold for f in findings) else 0


def _map(args: argparse.Namespace) -> int:
    try:
        with open_dicom(args.path) as ctx:
            if ctx is None:
                print(safe(f"{args.path}: not a regular DICOM Part 10 file"), file=sys.stderr)
                return 2
            for line in mapview.render(args.path, ctx.buf, ctx.parsed,
                                       max_depth=args.depth, show_phi=args.show_phi):
                print(safe(line))
    except OSError as exc:
        print(safe(f"{args.path}: {exc}"), file=sys.stderr)
        return 2
    return 0
