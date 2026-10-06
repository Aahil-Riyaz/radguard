"""Walk paths, identify DICOM Part 10 files, and run every registered check.

The scanner is the part of RadGuard that touches the file system, and the
directory being scanned may itself be hostile. See docs/security/self-audit.md.
"""

from __future__ import annotations

import mmap
import os
import stat
from collections import Counter
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field

from radguard.checks import ALL_CHECKS, Check
from radguard.context import HEADER_LEN, MAGIC, PREAMBLE_LEN, FileContext
from radguard.findings import Finding, Severity

# Files up to this size are read into memory; larger ones are memory-mapped.
# A mapped file that another process truncates raises SIGBUS on POSIX when the
# missing pages are touched, killing the process; a private copy cannot shrink.
READ_LIMIT = 64 << 20

# Findings kept per check id per file; the rest are summarised in one finding.
MAX_FINDINGS_PER_CHECK = 100

_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_BINARY", 0)  # Windows: no newline translation
    | getattr(os, "O_NONBLOCK", 0)  # POSIX: opening a FIFO must not wait for a writer
    | getattr(os, "O_NOCTTY", 0)  # POSIX: a terminal device never becomes our controlling tty
)


@dataclass
class FileResult:
    path: str
    is_dicom: bool
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None


def iter_files(paths: Iterable[str]) -> Iterator[str]:
    # DICOM files frequently have no extension (or numeric ones), so we
    # consider every regular file and let the magic bytes decide. os.walk does
    # not follow directory symlinks, so symlink loops cannot trap the walk.
    for path in paths:
        if os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                dirs.sort()
                for name in sorted(files):
                    yield os.path.join(root, name)
        else:
            yield path


@contextmanager
def open_dicom(path: str) -> Iterator[FileContext | None]:
    """Yield a FileContext for a regular Part 10 file, or None for anything else.

    Only regular files are ever read. A FIFO would block forever, a device
    could stream endlessly or have side effects on open (tape drives rewind).
    The cheap stat() filters the obvious cases without opening them; the
    authoritative check is fstat() on the descriptor we actually read, so
    swapping the path between the two calls gains an attacker nothing.
    """
    if not stat.S_ISREG(os.stat(path).st_mode):
        yield None
        return
    fd = os.open(path, _OPEN_FLAGS)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size < HEADER_LEN:
            yield None
            return
        if st.st_size <= READ_LIMIT:
            buf = _read(fd, st.st_size)
            yield FileContext(path, buf, len(buf)) if buf[PREAMBLE_LEN:HEADER_LEN] == MAGIC else None
            return
        with mmap.mmap(fd, 0, access=mmap.ACCESS_READ) as view:
            yield FileContext(path, view, len(view)) if view[PREAMBLE_LEN:HEADER_LEN] == MAGIC else None
    finally:
        os.close(fd)


def _read(fd: int, size: int) -> bytes:
    # The file may shrink while we read it; take what is there, never more than `size`.
    chunks, remaining = [], size
    while remaining:
        chunk = os.read(fd, min(remaining, 8 << 20))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def scan_file(path: str, checks: Iterable[Check] = ALL_CHECKS) -> FileResult:
    try:
        with open_dicom(path) as ctx:
            if ctx is None:
                return FileResult(path, is_dicom=False)
            findings, errors = [], []
            for check in checks:
                try:
                    findings.extend(check(ctx))
                except Exception as exc:  # a scanner must survive hostile input; report, don't crash
                    errors.append(f"{check.__module__}: {exc!r}")
            return FileResult(path, True, _cap(path, findings), "; ".join(errors) or None)
    except (OSError, ValueError, BufferError) as exc:
        return FileResult(path, is_dicom=False, error=str(exc))


def _cap(path: str, findings: list[Finding]) -> list[Finding]:
    """One file must not be able to flood the report (or the analyst's memory)."""
    kept, dropped = [], Counter()
    seen = Counter()
    for f in findings:
        seen[f.check] += 1
        if seen[f.check] <= MAX_FINDINGS_PER_CHECK:
            kept.append(f)
        else:
            dropped[f.check] += 1
    if dropped:
        summary = ", ".join(f"{n:,} x {check}" for check, n in dropped.most_common())
        kept.append(Finding("scan.findings-suppressed", Severity.MEDIUM, "Finding flood suppressed",
                            f"kept the first {MAX_FINDINGS_PER_CHECK} findings per check; suppressed {summary}",
                            path))
    return kept


def scan_paths(paths: Iterable[str], checks: Iterable[Check] = ALL_CHECKS) -> Iterator[FileResult]:
    checks = tuple(checks)
    for path in iter_files(paths):
        yield scan_file(path, checks)
