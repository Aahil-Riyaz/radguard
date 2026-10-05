"""Data model produced by the parser."""

from __future__ import annotations

from dataclasses import dataclass, field

UNDEFINED = 0xFFFFFFFF

ITEM = 0xFFFEE000
ITEM_DELIM = 0xFFFEE00D
SEQ_DELIM = 0xFFFEE0DD
TRANSFER_SYNTAX = 0x00020010
FLOAT_PIXEL_DATA = 0x7FE00008
DOUBLE_PIXEL_DATA = 0x7FE00009
PIXEL_DATA = 0x7FE00010
TRAILING_PADDING = 0xFFFCFFFC

# Byte-coverage classes. Every byte of a file is exactly one of these, or
# "unexplained" -- bytes the DICOM grammar cannot account for.
PREAMBLE = "preamble"
MAGIC = "magic"
HEADER = "header"
VALUE = "value"
PADDING = "padding"
DEFLATE = "deflate"
KINDS = (PREAMBLE, MAGIC, HEADER, VALUE, PADDING, DEFLATE)

Region = tuple[int, int, str]  # [start, end) and its coverage class


def tag_str(tag: int) -> str:
    return f"({tag >> 16:04X},{tag & 0xFFFF:04X})"


@dataclass(frozen=True)
class Syntax:
    uid: str | None
    name: str
    implicit: bool = False
    little: bool = True
    deflated: bool = False
    encapsulated: bool = False
    known: bool = True


@dataclass(slots=True)
class Element:
    tag: int
    vr: str  # "" for items
    vr_source: str  # explicit | dictionary | inferred | unknown | structural
    offset: int  # first byte of the element header
    value_offset: int  # first byte of the value
    length: int  # declared value length; UNDEFINED for undefined length
    end: int  # first byte after the element, including nested content and delimiters
    depth: int  # sequence nesting level; top-level dataset is 0
    parent: int | None  # index of the enclosing Item (or, for an Item, its sequence)
    little: bool
    domain: str = "file"  # "file", or "inflated" for deflated transfer syntaxes
    fragments: list[tuple[int, int]] | None = None  # encapsulated pixel data: (offset, length)

    @property
    def undefined(self) -> bool:
        return self.length == UNDEFINED


@dataclass(frozen=True, slots=True)
class Anomaly:
    code: str
    message: str
    offset: int
    tag: int | None = None
    domain: str = "file"


@dataclass
class ParsedFile:
    size: int
    syntax: Syntax
    meta_end: int
    elements: list[Element]
    anomalies: list[Anomaly]
    regions: list[Region]
    inflated: bytes | None = None
    inflated_regions: list[Region] = field(default_factory=list)

    @property
    def dataset_domain(self) -> str:
        return "inflated" if self.inflated is not None else "file"

    def buffer(self, domain: str, file_buf):
        return self.inflated if domain == "inflated" else file_buf
