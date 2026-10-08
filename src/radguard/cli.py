"""Command-line entry point: `radguard scan <paths...>`, `radguard map <file>` and `radguard rules`.

Exit status (scan):
  0  every path was examined and no finding reached --fail-on
  1  at least one finding reached --fail-on
  2  usage error (argparse)
  3  the scan or its report is incomplete: a path could not be read, a check
     failed, the report could not be written, or RadGuard itself failed.
     This takes precedence over 1, because a verdict built on partial
     coverage cannot be trusted; findings are still reported.

An unexpected exception must never look like a verdict. Python exits with
status 1 on an uncaught exception, which is the "findings" status, so a crash
while writing the report would have read as an ordinary result.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import sys
import tempfile
import traceback

from radguard import __version__, mapview, report, rules, sarif
from radguard.findings import Severity
from radguard.output import dumps, harden_streams, safe
from radguard.scanner import open_dicom, scan_paths

EXIT_CLEAN, EXIT_FINDINGS, EXIT_INCOMPLETE = 0, 1, 3
# Kept importable from here for existing callers.
JSON_SCHEMA_VERSION, SEVERITY_NAMES = report.JSON_SCHEMA_VERSION, report.SEVERITY_NAMES


def main(argv: list[str] | None = None) -> int:
    harden_streams()
    try:
        return _main(argv)
    except BrokenPipeError:
        # The reader went away (`radguard scan ... | head`): the report was not delivered in full.
        _discard_stdout()
        return EXIT_INCOMPLETE
    except Exception:
        for line in traceback.format_exc().splitlines():
            print(safe(line), file=sys.stderr)
        print("radguard: internal error; the report is incomplete (exit status 3)", file=sys.stderr)
        return EXIT_INCOMPLETE


def _main(argv: list[str] | None) -> int:
    parser = argparse.ArgumentParser(
        prog="radguard",
        description="Integrity and safety scanner for medical imaging (DICOM).",
        epilog="exit status: 0 clean, 1 findings at or above --fail-on, 2 usage error, 3 scan incomplete",
    )
    parser.add_argument("--version", action="version", version=f"radguard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan DICOM files and directories")
    scan.add_argument("paths", nargs="+", help="files or directories (searched recursively)")
    scan.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    scan.add_argument("-o", "--output", metavar="FILE",
                      help="write the report to FILE (UTF-8, replaced atomically) instead of standard output")
    scan.add_argument(
        "--fail-on", choices=SEVERITY_NAMES, default="high",
        help="exit with status 1 if any finding is at least this severe (default: high)",
    )

    mp = sub.add_parser("map", help="show the byte-level structure of one DICOM file")
    mp.add_argument("path")
    mp.add_argument("--depth", type=int, help="hide elements nested deeper than this many sequences")
    mp.add_argument("--show-phi", action="store_true", help="show patient-identifying values instead of masking them")

    rl = sub.add_parser("rules", help="list every rule RadGuard can report")
    rl.add_argument("--markdown", action="store_true", help="print the rule reference (docs/rules.md)")

    args = parser.parse_args(argv)
    if args.command == "map":
        return _map(args)
    if args.command == "rules":
        print(rules.reference() if args.markdown else rules.listing(), end="")
        return EXIT_CLEAN
    return _scan(args)


def _scan(args: argparse.Namespace) -> int:
    result = report.collect(scan_paths(args.paths))
    if not result.complete:
        status = EXIT_INCOMPLETE
    else:
        status = EXIT_FINDINGS if result.reaches(Severity.parse(args.fail_on)) else EXIT_CLEAN

    if args.format == "text":
        text = "\n".join(report.to_text(result)) + "\n"
    elif args.format == "json":
        text = dumps(report.to_json(result))
    else:
        text = dumps(sarif.to_sarif(result, os.getcwd(), exit_code=status))

    delivered = _deliver(text, args.output)
    for line in report.diagnostics(result):
        print(line, file=sys.stderr)
    return status if delivered else EXIT_INCOMPLETE


def _deliver(text: str, path: str | None) -> bool:
    if path is None:
        sys.stdout.write(text)
        sys.stdout.flush()
        return True
    try:
        _write_atomically(path, text)
    except OSError as exc:
        print(safe(f"radguard: cannot write {path}: {exc.strerror or exc}"), file=sys.stderr)
        return False
    return True


def _write_atomically(path: str, text: str) -> None:
    """Write UTF-8 to a temporary file beside `path`, then rename it over `path`.

    A consumer (a CI upload step, a SIEM collector) sees either the previous
    report or the complete new one, never a truncated file. Writing the file
    ourselves also avoids shell redirection: Windows PowerShell 5.1's `>`
    writes UTF-16, which SARIF and JSON consumers reject. The file is created
    readable by its owner only, since a report says where sensitive data and
    malware live.
    """
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".radguard-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _discard_stdout() -> None:
    # Python flushes stdout again at exit; point it at the null device so that flush cannot fail too.
    with contextlib.suppress(OSError, ValueError, AttributeError):
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())


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
