"""Walk paths, identify DICOM Part 10 files, and run every registered check."""

from __future__ import annotations

import mmap
import os
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field

from radguard.checks import ALL_CHECKS, Check
from radguard.context import HEADER_LEN, MAGIC, PREAMBLE_LEN, FileContext
from radguard.findings import Finding


@dataclass
class FileResult:
    path: str
    is_dicom: bool
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None


def iter_files(paths: Iterable[str]) -> Iterator[str]:
    # DICOM files frequently have no extension (or numeric ones), so we
    # consider every regular file and let the magic bytes decide.
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
    """Memory-map `path` read-only; yield a FileContext, or None if it is not a Part 10 file.

    Mapping instead of reading means multi-gigabyte studies cost no RAM and
    checks can jump to any offset without copying.
    """
    with open(path, "rb") as fh:
        size = os.fstat(fh.fileno()).st_size
        if size < HEADER_LEN:
            yield None
            return
        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as buf:
            yield FileContext(path, buf, size) if buf[PREAMBLE_LEN:HEADER_LEN] == MAGIC else None


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
            return FileResult(path, True, findings, "; ".join(errors) or None)
    except (OSError, ValueError) as exc:
        return FileResult(path, is_dicom=False, error=str(exc))


def scan_paths(paths: Iterable[str], checks: Iterable[Check] = ALL_CHECKS) -> Iterator[FileResult]:
    checks = tuple(checks)
    for path in iter_files(paths):
        yield scan_file(path, checks)
