"""Finding model shared by every check."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str) -> Severity:
        return cls[value.upper()]


@dataclass(frozen=True)
class Finding:
    check: str  # stable id, e.g. "preamble.pe-polyglot"
    severity: Severity
    title: str
    detail: str
    path: str
    offset: int | None = None
    references: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "check": self.check,
            "severity": str(self.severity),
            "title": self.title,
            "detail": self.detail,
            "path": self.path,
            "offset": self.offset,
            "references": list(self.references),
        }
