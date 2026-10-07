"""Per-file state handed to every check."""

from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property

from radguard.carving import MatchIndex, carve
from radguard.dicom import ParsedFile, parse
from radguard.dicom.model import Buffer

PREAMBLE_LEN = 128
MAGIC = b"DICM"
HEADER_LEN = PREAMBLE_LEN + len(MAGIC)


@dataclass
class FileContext:
    path: str
    buf: Buffer
    size: int
    part10: bool = True  # False: a bare dataset (no preamble or DICM marker)

    @property
    def preamble(self) -> bytes:
        return bytes(self.buf[:PREAMBLE_LEN]) if self.part10 else b""

    @cached_property
    def parsed(self) -> ParsedFile:
        # Parsed once, shared by every check that needs structure.
        return parse(self.buf, part10=self.part10)

    @cached_property
    def _indexes(self) -> dict[str, MatchIndex]:
        indexes = {"file": carve(self.buf)}
        if self.parsed.inflated is not None:
            indexes["inflated"] = carve(self.parsed.inflated)
        return indexes

    def matches(self, domain: str = "file") -> MatchIndex:
        """Embedded-file matches for the whole buffer of `domain`, searched once and shared."""
        return self._indexes[domain]
