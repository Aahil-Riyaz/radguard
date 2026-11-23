"""Walk paths, identify DICOM files, and run every registered check.

The scanner is the part of RadGuard that touches the file system, and the
directory being scanned may itself be hostile. It fails closed: anything it
could not examine (an unreadable directory, an unreadable file, a check that
crashed) is reported as an error, never silently dropped, so a scan that saw
less than it was asked to can never look clean. See docs/security/self-audit.md.
"""

from __future__ import annotations

import mmap
import os
import stat
import sys
from collections import Counter, deque
from collections.abc import Iterable, Iterator
from concurrent.futures import Future, ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
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

# Files handed to a worker process at a time. One task per file would spend more time
# on inter-process messaging than on scanning small files; see docs/results.md.
DEFAULT_BATCH = 32  # pragma: no mutate (tuning)
# Batches queued per worker: enough to keep every worker busy, small enough that memory
# stays bounded however large the tree is.
WINDOW_PER_WORKER = 4  # pragma: no mutate (tuning)
# ProcessPoolExecutor cannot wait on more than 61 workers on Windows.
MAX_JOBS = 61 if sys.platform == "win32" else 256  # pragma: no mutate (platform limit)

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


def resolve_jobs(jobs: int) -> int:
    """Number of worker processes for a --jobs value: 0 means one per CPU, never above MAX_JOBS."""
    if jobs < 0:
        raise ValueError("jobs must be 0 (one per CPU) or a positive number")
    return min(jobs or os.cpu_count() or 1, MAX_JOBS)


def scan_paths(paths: Iterable[str], checks: Iterable[Check] = ALL_CHECKS, *,
               jobs: int = 1, batch_size: int = DEFAULT_BATCH) -> Iterator[FileResult]:
    """Scan files and directory trees. DICOM files often have no extension, so every
    regular file is considered and its first bytes decide.

    With ``jobs > 1`` files are scanned by that many worker processes, but the results
    come back in exactly the order a serial scan produces, so the report never depends on
    how many workers ran. Output is identical; only the wall-clock time changes."""
    checks = tuple(checks)
    jobs = resolve_jobs(jobs)
    if jobs <= 1:
        for item in _walk(paths):
            yield scan_file(item, checks) if isinstance(item, str) else item
        return
    yield from _scan_parallel(paths, checks, jobs, max(1, batch_size))


def _walk(paths: Iterable[str]) -> Iterator[str | FileResult]:
    """Yield every path to scan, in report order, and a FileResult for anything the walk
    itself already decided (an unreadable directory, a symlink that is not followed)."""
    for path in paths:
        if not os.path.isdir(path):
            yield path
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
                yield os.path.join(root, name)
        yield from _walk_errors(errors)


def _batches(paths: Iterable[str], size: int) -> Iterator[list[str] | FileResult]:
    """Group the walk into batches of `size` files. A FileResult flushes the batch first, so
    the original order is preserved exactly."""
    batch: list[str] = []
    for item in _walk(paths):
        if isinstance(item, str):
            batch.append(item)
            if len(batch) >= size:
                yield batch
                batch = []
        else:
            if batch:
                yield batch
                batch = []
            yield item
    if batch:
        yield batch


def _scan_batch(paths: tuple[str, ...], checks: tuple[Check, ...]) -> list[FileResult]:
    """Runs in a worker process."""
    return [scan_file(path, checks) for path in paths]


class _Workers:
    """A process pool that replaces itself after a worker dies, so one hostile file that
    kills its worker cannot take the rest of the scan with it."""

    def __init__(self, jobs: int) -> None:
        self._jobs = jobs
        self._pool = ProcessPoolExecutor(max_workers=jobs)

    def submit(self, paths: list[str], checks: tuple[Check, ...]) -> Future[list[FileResult]]:
        try:
            return self._pool.submit(_scan_batch, tuple(paths), checks)
        except BrokenProcessPool:
            self._pool.shutdown(wait=False, cancel_futures=True)
            self._pool = ProcessPoolExecutor(max_workers=self._jobs)
            return self._pool.submit(_scan_batch, tuple(paths), checks)

    def close(self) -> None:
        self._pool.shutdown(wait=True, cancel_futures=True)


def _scan_parallel(paths: Iterable[str], checks: tuple[Check, ...], jobs: int,
                   batch_size: int) -> Iterator[FileResult]:
    workers = _Workers(jobs)
    queue: deque[tuple[list[str] | FileResult, Future[list[FileResult]] | None]] = deque()
    window = jobs * WINDOW_PER_WORKER
    try:
        for unit in _batches(paths, batch_size):
            queue.append((unit, workers.submit(unit, checks) if isinstance(unit, list) else None))
            while len(queue) >= window:
                yield from _collect(*queue.popleft(), checks)
        while queue:
            yield from _collect(*queue.popleft(), checks)
    finally:
        workers.close()


def _collect(unit: list[str] | FileResult, future: Future[list[FileResult]] | None,
             checks: tuple[Check, ...]) -> Iterator[FileResult]:
    if future is None:
        assert isinstance(unit, FileResult)
        yield unit
        return
    assert isinstance(unit, list)
    try:
        yield from future.result()
    except BrokenProcessPool:
        # A worker died (killed, out of memory, or a crash in native code) and the pool cannot
        # say which file did it. Re-run each file of this batch alone in a fresh process: the
        # culprit is then named exactly and reported as an error, which makes the scan
        # incomplete (exit status 3) instead of looking clean.
        for path in unit:
            yield _scan_isolated(path, checks)
    except Exception as exc:  # e.g. a custom check that cannot be pickled
        for path in unit:
            yield FileResult(path, is_dicom=False, error=f"worker failed: {exc!r}")


def _scan_isolated(path: str, checks: tuple[Check, ...]) -> FileResult:
    with ProcessPoolExecutor(max_workers=1) as one:
        try:
            return one.submit(_scan_batch, (path,), checks).result()[0]
        except BrokenProcessPool:
            return FileResult(path, is_dicom=False,
                              error="the scanner process died while examining this file")
        except Exception as exc:
            return FileResult(path, is_dicom=False, error=f"worker failed: {exc!r}")


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
            yield None
            return
        buf = head + _read(fd, st.st_size - len(head))
        yield _context(path, buf)
    finally:
        os.close(fd)


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
            return FileResult(path, True, _cap(path, findings), "; ".join(errors) or None)
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
