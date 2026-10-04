"""Per-file state handed to every check."""

from __future__ import annotations

from dataclasses import dataclass
from typing import BinaryIO

PREAMBLE_LEN = 128
MAGIC = b"DICM"
HEADER_LEN = PREAMBLE_LEN + len(MAGIC)


@dataclass
class FileContext:
    path: str
    fh: BinaryIO  # opened in binary mode; checks may seek freely
    size: int
    preamble: bytes  # always exactly PREAMBLE_LEN bytes
