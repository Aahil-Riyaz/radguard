"""Command-line entry point: `radguard scan <paths...>` and `radguard map <file>`.

Exit status (scan):
  0  every path was examined and no finding reached --fail-on
  1  at least one finding reached --fail-on
  2  usage error (argparse)
  3  the scan was incomplete: a path could not be read or a check failed.
     This takes precedence over 1, because a verdict built on partial
     coverage cannot be trusted; findings are still reported.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter

from radguard import __version__, mapview
from radguard.findings import Finding, Severity
from radguard.output import safe
from radguard.scanner import open_dicom, scan_paths

SEVERITY_NAMES = [str(s) for s in Severity]
EXIT_CLEAN, EXIT_FINDINGS, EXIT_INCOMPLETE = 0, 1, 3
JSON_SCHEMA_VERSION = 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="radguard",
        description="Integrity and safety scanner for medical imaging (DICOM).",
        epilog="exit status: 0 clean, 1 findings at or above --fail-on, 2 usage error, 3 scan incomplete",
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
    findings: list[Finding] = []
    errors: list[dict[str, str]] = []
    notes: list[dict[str, str]] = []
    files = dicom = skipped = 0

    for result in scan_paths(args.paths):
        if result.note:
            notes.append({"path": result.path, "note": result.note})
            continue
        files += 1
        dicom += result.is_dicom
        skipped += not result.is_dicom and not result.error
        findings.extend(result.findings)
        if result.error:
            errors.append({"path": result.path, "error": result.error})

    findings.sort(key=lambda f: (-f.severity, f.path, f.offset or 0))
    by_severity = Counter(str(f.severity) for f in findings)
    counts = {name: by_severity.get(name, 0) for name in reversed(SEVERITY_NAMES)}

    if args.format == "json":
        report = {
            "tool": {"name": "radguard", "version": __version__},
            "schema_version": JSON_SCHEMA_VERSION,
            "summary": {"files": files, "dicom": dicom, "skipped": skipped, "errors": len(errors),
                        "notes": len(notes), "complete": not errors, "findings": counts},
            "findings": [f.to_dict() for f in findings],
            "errors": errors,
            "notes": notes,
        }
        json.dump(report, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        # Paths and details carry attacker-controlled text: everything printed goes through safe().
        for f in findings:
            print(safe(f"{str(f.severity).upper():<9} {f.check:<34} {f.path}"))
            print(safe(f"{'':<9} {f.title}"))
            print(safe(f"{'':<9} {f.detail}"))
        for e in errors:
            print(safe(f"{'ERROR':<9} {e['path']}: {e['error']}"), file=sys.stderr)
        for n in notes:
            print(safe(f"{'NOTE':<9} {n['path']}: {n['note']}"), file=sys.stderr)
        found = ", ".join(f"{name}={count}" for name, count in counts.items() if count)
        print(f"\nscanned {files} files: {dicom} DICOM, {skipped} skipped, {len(errors)} errors"
              f"{f', {len(notes)} notes' if notes else ''}; findings: {found or 'none'}")
        if errors:
            print("scan INCOMPLETE: some paths could not be examined (exit status 3)", file=sys.stderr)

    if errors:
        return EXIT_INCOMPLETE
    return EXIT_FINDINGS if any(f.severity >= threshold for f in findings) else EXIT_CLEAN


def _map(args: argparse.Namespace) -> int:
    try:
        with open_dicom(args.path) as ctx:
            if ctx is None:
                print(safe(f"{args.path}: not a regular DICOM file"), file=sys.stderr)
                return EXIT_INCOMPLETE
            for line in mapview.render(args.path, ctx.buf, ctx.parsed,
                                       max_depth=args.depth, show_phi=args.show_phi):
                print(safe(line))
    except OSError as exc:
        print(safe(f"{args.path}: {exc}"), file=sys.stderr)
        return EXIT_INCOMPLETE
    return EXIT_CLEAN
