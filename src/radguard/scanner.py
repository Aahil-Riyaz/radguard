"""Walk paths, identify DICOM Part 10 files, and run every registered check."""

from __future__ import annotations

import os
from collections.abc import Iterable, Iterator
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


def scan_file(path: str, checks: Iterable[Check] = ALL_CHECKS) -> FileResult:
    try:
        with open(path, "rb") as fh:
            header = fh.read(HEADER_LEN)
            if len(header) < HEADER_LEN or header[PREAMBLE_LEN:] != MAGIC:
                return FileResult(path, is_dicom=False)
            ctx = FileContext(
                path=path,
                fh=fh,
                size=os.fstat(fh.fileno()).st_size,
                preamble=header[:PREAMBLE_LEN],
            )
            findings = [f for check in checks for f in check(ctx)]
    except OSError as exc:
        return FileResult(path, is_dicom=False, error=str(exc))
    return FileResult(path, is_dicom=True, findings=findings)


def scan_paths(paths: Iterable[str], checks: Iterable[Check] = ALL_CHECKS) -> Iterator[FileResult]:
    checks = tuple(checks)
    for path in iter_files(paths):
        yield scan_file(path, checks)
