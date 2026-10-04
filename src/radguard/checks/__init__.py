"""Registry of file-level checks. Each check takes a FileContext and yields Findings."""

from __future__ import annotations

from collections.abc import Callable, Iterable

from radguard.checks import preamble
from radguard.context import FileContext
from radguard.findings import Finding

Check = Callable[[FileContext], Iterable[Finding]]

ALL_CHECKS: tuple[Check, ...] = (
    preamble.check,
)
