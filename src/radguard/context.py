"""Per-file state handed to every check."""

from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property

from radguard.dicom import ParsedFile, parse

PREAMBLE_LEN = 128
MAGIC = b"DICM"
HEADER_LEN = PREAMBLE_LEN + len(MAGIC)


@dataclass
class FileContext:
    path: str
    buf: bytes  # or a read-only mmap: anything supporting len, slicing, find and struct
    size: int

    @property
    def preamble(self) -> bytes:
        return bytes(self.buf[:PREAMBLE_LEN])

    @cached_property
    def parsed(self) -> ParsedFile:
        # Parsed once, shared by every check that needs structure.
        return parse(self.buf)
