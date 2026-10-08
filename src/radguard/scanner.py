"""Walk paths, identify DICOM files, and run every registered check.

The scanner is the part of RadGuard that touches the file system, and the
directory being scanned may itself be hostile. It fails closed: anything it
could not examine (an unreadable directory, an unreadable file, a check that
crashed) is reported as an error, never silently dropped, so a scan that saw
less than it was asked to can never look clean. See docs/security/self-audit.md.
"""

from __future__ import annotations

import hashlib
import mmap
import os
import stat
from collections import Counter
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field

from radguard.checks import ALL_CHECKS, Check
from radguard.context import HEADER_LEN, MAGIC, PREAMBLE_LEN, FileContext
from radguard.dicom import looks_like_dataset
from radguard.dicom.model import Buffer
from radguard.findings import Finding, Severity

# Files up to this size are read into memory; larger ones are memory-mapped.
# A mapped file that another process truncates raises SIGBUS on POSIX when the
# missing pages are touched, killing the process; a private copy cannot shrink.
READ_LIMIT = 64 << 20  # pragma: no mutate (tuning)
SNIFF_LEN = 4096  # enough to recognise a DICOM file before reading the rest of it; pragma: no mutate (tuning)

# Findings kept per check id per file; the rest are summarised in one finding.
MAX_FINDINGS_PER_CHECK = 100  # pragma: no mutate (tuning)

_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_BINARY", 0)  # Windows: no newline translation; pragma: no mutate (platform default)
    | getattr(os, "O_NONBLOCK", 0)  # POSIX: opening a FIFO must not wait for a writer
    | getattr(os, "O_NOCTTY", 0)  # POSIX: a terminal device never becomes our controlling tty
)


@dataclass
class FileResult:
    path: str
    is_dicom: bool
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None  # the path could not be examined (fully)
    note: str | None = None  # deliberately not examined, and why
    size: int | None = None  # bytes examined
    sha256: str | None = None  # of exactly the bytes examined, for files with findings or errors


def scan_paths(paths: Iterable[str], checks: Iterable[Check] = ALL_CHECKS) -> Iterator[FileResult]:
    """Scan files and directory trees. DICOM files often have no extension, so every
    regular file is considered and its first bytes decide."""
    checks = tuple(checks)
    for path in paths:
        if not os.path.isdir(path):
            yield scan_file(path, checks)
            continue
        errors: list[OSError] = []  # os.walk reports unreadable directories here, not by raising
        for root, dirs, files in os.walk(path, onerror=errors.append):
            yield from _walk_errors(errors)
            dirs.sort()
            for name in dirs:
                if os.path.islink(os.path.join(root, name)):  # os.walk does not descend into these
                    yield FileResult(os.path.join(root, name), is_dicom=False,
                                     note="symbolic link to a directory: not followed")
            for name in sorted(files):
                yield scan_file(os.path.join(root, name), checks)
        yield from _walk_errors(errors)


def _walk_errors(errors: list[OSError]) -> Iterator[FileResult]:
    for exc in errors:
        yield FileResult(str(exc.filename), is_dicom=False, error=f"cannot list directory: {exc.strerror}")
    errors.clear()


@contextmanager
def open_dicom(path: str) -> Iterator[FileContext | None]:
    """Yield a FileContext for a regular DICOM file, or None for anything else.

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
        if not stat.S_ISREG(st.st_mode):
            yield None
            return
        if st.st_size > READ_LIMIT:
            with mmap.mmap(fd, 0, access=mmap.ACCESS_READ) as view:
                yield _context(path, view)
            return
        head = _read(fd, min(st.st_size, SNIFF_LEN))
        if _context(path, head) is None:  # decide before reading the rest of a large non-DICOM file
            if is_lfs_pointer(head):
                raise NotCheckedOut(LFS_MESSAGE)
            yield None
            return
        buf = head + _read(fd, st.st_size - len(head))
        yield _context(path, buf)
    finally:
        os.close(fd)


class NotCheckedOut(OSError):
    """The path holds a placeholder for the file, not the file: its content cannot be examined."""


# A Git LFS pointer stands in for a file whose content was not fetched, typically in CI that checks out
# without LFS. Skipping it as "not DICOM" would pass a scan that never saw the file, so it is an error.
LFS_VERSION = b"version https://git-lfs.github.com/spec/v1\n"
LFS_MAX = 1024  # the LFS specification limits pointer files to under 1024 bytes
LFS_MESSAGE = ("Git LFS pointer: the file's content is not checked out, so it was not scanned "
               "(fetch it with git lfs pull, or check out with lfs: true in GitHub Actions)")


def is_lfs_pointer(head: bytes) -> bool:
    return len(head) < LFS_MAX and head.startswith(LFS_VERSION) and b"\noid sha256:" in head and b"\nsize " in head


def _context(path: str, buf: Buffer) -> FileContext | None:
    if len(buf) >= HEADER_LEN and buf[PREAMBLE_LEN:HEADER_LEN] == MAGIC:
        return FileContext(path, buf, len(buf))
    if looks_like_dataset(buf):
        return FileContext(path, buf, len(buf), part10=False)
    return None


def _read(fd: int, size: int) -> bytes:
    # The file may shrink while we read it; take what is there, never more than `size`.
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = os.read(fd, min(remaining, 8 << 20))  # pragma: no mutate (tuning)
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
            findings: list[Finding] = []
            errors: list[str] = []
            for check in checks:
                try:
                    findings.extend(check(ctx))
                except Exception as exc:  # a scanner must survive hostile input; report, don't crash
                    errors.append(f"{check.__module__}: {exc!r}")
            # The digest identifies exactly the bytes the findings describe, even if the file changes later.
            digest = hashlib.sha256(ctx.buf).hexdigest() if findings or errors else None
            return FileResult(path, True, _cap(path, findings), "; ".join(errors) or None, size=ctx.size,
                              sha256=digest)
    except (OSError, ValueError, BufferError) as exc:
        return FileResult(path, is_dicom=False, error=str(exc))


def _cap(path: str, findings: list[Finding]) -> list[Finding]:
    """One file must not be able to flood the report (or the analyst's memory)."""
    kept: list[Finding] = []
    seen: Counter[str] = Counter()
    dropped: Counter[str] = Counter()
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
