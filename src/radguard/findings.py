"""Finding model shared by every check."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

# What a finding's offset counts bytes of. A deflated file (transfer syntax 1.2.840.10008.1.2.1.99) is
# analysed after decompression, and an offset into the decompressed dataset is not a position in the file.
FILE, INFLATED = "file", "inflated"


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4  # pragma: no mutate (equivalent: only the order of the values is ever used)

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
    domain: str = FILE  # FILE or INFLATED: what `offset` counts bytes of

    def to_dict(self) -> dict[str, object]:
        return {
            "check": self.check,
            "severity": str(self.severity),
            "title": self.title,
            "detail": self.detail,
            "path": self.path,
            "offset": self.offset,
            "domain": self.domain,
            "references": list(self.references),
        }
