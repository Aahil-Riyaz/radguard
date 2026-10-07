"""Hardened, offset-preserving DICOM Part 10 parser.

Why not pydicom? pydicom is built to *read* DICOM, so it is forgiving: it
guesses past broken structure, keeps one copy of a duplicated attribute and
never reports bytes it could not place. A security scanner needs the
opposite -- see the file exactly as its author wrote it. This parser:

* classifies every byte (preamble, magic, element header, value, padding,
  deflate stream), so whatever is left over is, by definition, hidden;
* never raises on malformed input: problems become Anomaly records and
  parsing resumes at the nearest boundary whose length can still be trusted;
* bounds its own resource use (nesting depth, element count, inflated size);
* records every ambiguity that makes real-world parsers disagree instead of
  silently choosing one interpretation.

See docs/design/parser.md for the design and its threat model.
"""

from __future__ import annotations

import struct
import zlib
from collections import Counter
from dataclasses import dataclass, field

from radguard.dicom import dictionary, uids
from radguard.dicom.model import (
    DEFLATE, HEADER, ITEM, ITEM_DELIM, MAGIC, PADDING, PIXEL_DATA, PREAMBLE, SEQ_DELIM,
    TRAILING_PADDING, TRANSFER_SYNTAX, UNDEFINED, VALUE, Anomaly, Buffer, Element, ParsedFile,
    Region, Syntax, tag_str,
)

PREAMBLE_LEN = 128
HEADER_LEN = 132  # preamble + "DICM"

_VALID_VRS = frozenset(
    b"AE AS AT CS DA DS DT FL FD IS LO LT OB OD OF OL OV OW PN "
    b"SH SL SQ SS ST SV TM UC UI UL UN UR US UT UV".split()
)
# VRs with a 2-byte reserved field and a 4-byte length when explicit (PS3.5 7.1.2).
_LONG_VRS = frozenset(b"OB OD OF OL OV OW SQ UC UN UR UT SV UV".split())
_FIXED_SIZE = {"US": 2, "SS": 2, "UL": 4, "SL": 4, "FL": 4, "AT": 4, "FD": 8, "SV": 8, "UV": 8}
_ENCODINGS = {
    (True, True): "Implicit VR Little Endian",
    (False, True): "Explicit VR Little Endian",
    (False, False): "Explicit VR Big Endian",
}


# Each nesting level costs three Python frames (dataset -> value -> sequence);
# this ceiling keeps the deepest permitted parse far from the interpreter's
# recursion limit, so no Limits value can turn into a RecursionError.
MAX_DEPTH_CEILING = 128  # pragma: no mutate (tuning)
# Anomalies kept per code per file; the rest are counted and summarised.
MAX_ANOMALIES_PER_CODE = 50


@dataclass(frozen=True)
class Limits:
    max_depth: int = 32  # pragma: no mutate (tuning)
    max_elements: int = 1_000_000  # pragma: no mutate (tuning)
    max_inflated: int = 256 << 20  # pragma: no mutate (tuning)

    def __post_init__(self) -> None:
        if not 1 <= self.max_depth <= MAX_DEPTH_CEILING:
            raise ValueError(f"max_depth must be between 1 and {MAX_DEPTH_CEILING}")
        if self.max_elements < 1 or self.max_inflated < 0:
            raise ValueError("max_elements must be positive and max_inflated non-negative")


@dataclass
class _Tally:
    """Anomaly counts shared by every parser working on one file."""
    counts: Counter[str] = field(default_factory=Counter)
    first_suppressed: dict[str, int] = field(default_factory=dict)
    total: int = 0  # pragma: no mutate (equivalent: only compared for equality)


class _Desync(Exception):
    """Structure is lost; unwind to the nearest defined-length boundary."""


def parse(buf: Buffer, limits: Limits = Limits(), *, part10: bool = True) -> ParsedFile:
    """Parse a DICOM file held in `buf` (bytes or a read-only mmap).

    `part10` files start with the 128-byte preamble and "DICM". Otherwise `buf` is a
    bare dataset, which strict readers reject but lenient ones (pydicom's force mode,
    many toolkits) read anyway, so RadGuard must analyse it rather than skip it.
    """
    tally = _Tally()
    result = _parse(buf, limits, tally, part10)
    for code, offset in tally.first_suppressed.items():
        extra = tally.counts[code] - MAX_ANOMALIES_PER_CODE
        result.anomalies.append(Anomaly("suppressed", f"{extra:,} more '{code}' anomalies were not recorded", offset))
    return result


def _parse(buf: Buffer, limits: Limits, tally: _Tally, part10: bool) -> ParsedFile:
    anomalies: list[Anomaly] = []
    elements: list[Element] = []
    p = _Parser(buf, limits, "file", anomalies, elements, tally)
    start = HEADER_LEN if part10 else 0
    if part10:
        p.region(0, PREAMBLE_LEN, PREAMBLE)
        p.region(PREAMBLE_LEN, HEADER_LEN, MAGIC)
    else:
        p.note("no-part10-header", "the file has no 128-byte preamble or DICM marker; it is a bare dataset", 0)

    # File Meta Information: group 0002, always Explicit VR Little Endian (PS3.10 7.1).
    try:
        pos, _ = p.dataset(start, p.size, 0, None, False, True, only_group=0x0002)
    except _Desync:
        return ParsedFile(p.size, uids.lookup(None), start, elements, anomalies, p.regions, part10=part10)

    ts = p.transfer_syntax()
    if not part10 and pos == start:
        # A bare dataset without File Meta declares nothing: infer the encoding.
        implicit, little = p.detect(pos)
        syntax = Syntax(None, f"{_ENCODINGS[(implicit, little)]} (inferred: no File Meta)", implicit, little)
    else:
        syntax = uids.lookup(ts)
        if not any(el.tag == 0x00020000 for el in elements):
            p.note("missing-meta-group-length",
                   "File Meta has no group length (0002,0000), which PS3.10 requires", start)
        if ts is None:
            p.note("missing-transfer-syntax",
                   "File Meta has no Transfer Syntax UID (0002,0010); readers must guess the encoding", start)
        elif not syntax.known:
            p.note("unknown-transfer-syntax", f"Transfer Syntax UID {ts!r} is not a standard transfer syntax",
                   start, TRANSFER_SYNTAX)

    result = ParsedFile(p.size, syntax, pos, elements, anomalies, p.regions, part10=part10)
    if pos >= p.size:
        return result

    if syntax.deflated:
        data = p.inflate(pos)
        if data is not None:
            inner = _Parser(data, limits, "inflated", anomalies, elements, tally)
            try:
                inner.dataset(0, len(data), 0, None, False, True)
            except _Desync:
                pass
            result.inflated, result.inflated_regions = data, inner.regions
        return result

    implicit, little = p.sniff(pos, syntax)  # for an inferred encoding, sniff confirms it without an anomaly
    try:
        p.dataset(pos, p.size, 0, None, implicit, little)
    except _Desync:
        pass  # the remainder of the file stays unexplained
    return result


class _Parser:
    def __init__(self, buf: Buffer, limits: Limits, domain: str, anomalies: list[Anomaly], elements: list[Element],
                 tally: _Tally):
        self.tally = tally
        self.buf = buf
        self.size = len(buf)
        self.limits = limits
        self.domain = domain
        self.anomalies = anomalies
        self.elements = elements
        self.regions: list[Region] = []

    def note(self, code: str, message: str, offset: int, tag: int | None = None) -> None:
        tally = self.tally
        tally.total += 1  # pragma: no mutate (equivalent: only compared for equality)
        tally.counts[code] += 1
        if tally.counts[code] > MAX_ANOMALIES_PER_CODE:
            tally.first_suppressed.setdefault(code, offset)
            return
        self.anomalies.append(Anomaly(code, message, offset, tag, self.domain))

    def region(self, start: int, end: int, kind: str) -> None:
        if end > start:
            self.regions.append((start, end, kind))

    def admit(self, pos: int, tag: int) -> None:
        if len(self.elements) >= self.limits.max_elements:
            self.note("element-limit",
                      f"more than {self.limits.max_elements:,} elements; refusing to parse further", pos, tag)
            raise _Desync

    # -- element headers ------------------------------------------------------

    def header(self, pos: int, end: int, implicit: bool, little: bool) -> tuple[int, str | None, int, int]:
        """Decode the element header at `pos` into (tag, vr or None, length, value offset)."""
        buf = self.buf
        if pos + 8 > end:
            self.note("truncated-header", f"{end - pos} bytes remain, too few for an element header", pos)
            raise _Desync
        e = "<" if little else ">"
        group, elem = struct.unpack_from(e + "HH", buf, pos)
        tag = group << 16 | elem
        if implicit or group == 0xFFFE:  # items and delimiters never carry a VR
            (length,) = struct.unpack_from(e + "I", buf, pos + 4)
            return tag, None, length, pos + 8
        vr = bytes(buf[pos + 4 : pos + 6])
        if vr not in _VALID_VRS:
            self.note("invalid-vr", f"{tag_str(tag)} has VR bytes {vr.hex(' ')}, which is not a VR", pos, tag)
            raise _Desync
        if vr in _LONG_VRS:
            if pos + 12 > end:
                self.note("truncated-header", f"{end - pos} bytes remain, too few for a {vr.decode()} header", pos)
                raise _Desync
            reserved, length = struct.unpack_from(e + "HI", buf, pos + 6)
            if reserved:
                self.note("reserved-nonzero", f"{tag_str(tag)} reserved header bytes are {reserved:#06x}", pos, tag)
            return tag, vr.decode(), length, pos + 12
        (length,) = struct.unpack_from(e + "H", buf, pos + 6)
        return tag, vr.decode(), length, pos + 8

    # -- datasets ---------------------------------------------------------------

    def dataset(self, pos: int, end: int, depth: int, parent: int | None, implicit: bool, little: bool,
                *, in_item: bool = False, only_group: int | None = None) -> tuple[int, bool]:
        """Parse elements in [pos, end). Returns (position reached, closed by Item Delimitation Item)."""
        e = "<" if little else ">"
        prev, seen = -1, set()  # pragma: no mutate (equivalent: any start below the first tag)
        glen = None  # (group, where its group length says it ends, offset of the length element)
        while pos < end:
            if only_group is not None and (
                    pos + 2 > end  # pragma: no mutate (equivalent: the dataset parse reports the same truncation)
                    or struct.unpack_from(e + "H", self.buf, pos)[0] != only_group):
                break
            tag, vr, length, voff = self.header(pos, end, implicit, little)
            group = tag >> 16
            if glen and group != glen[0]:
                self._group_length(glen, pos)
                glen = None

            if group == 0xFFFE:
                if in_item and tag == ITEM_DELIM:
                    if length:
                        self.note("delimiter-length", f"Item Delimitation Item has length {length}, not 0", pos, tag)
                    self.region(pos, voff, HEADER)
                    return voff, True
                if in_item and tag == SEQ_DELIM:
                    self.note("missing-item-delimiter",
                              "sequence ends while an undefined-length item is still open", pos, tag)
                    return pos, True
                self.note("stray-delimiter", f"{tag_str(tag)} appears outside the structure it belongs to", pos, tag)
                raise _Desync

            self.admit(pos, tag)
            if tag in seen:
                self.note("duplicate-tag", f"{tag_str(tag)} appears more than once in the same dataset", pos, tag)
            elif tag < prev:  # pragma: no mutate (equivalent: an equal tag is caught as a duplicate)
                self.note("tag-order", f"{tag_str(tag)} comes after {tag_str(prev)}; tags must ascend", pos, tag)
            seen.add(tag)
            prev = max(prev, tag)

            source = "explicit"
            if vr is None:
                vr, source = dictionary.vr(tag), "dictionary"
                if vr is None:
                    vr, source = "UN", "unknown"
            el = Element(tag, vr, source, pos, voff, length, voff, depth, parent, little, self.domain)
            idx = len(self.elements)
            self.elements.append(el)
            self.region(pos, voff, HEADER)
            self._check_vr(el)

            if length == UNDEFINED:
                pos = self._undefined(el, idx, end, depth, implicit, little)
            else:
                pos = self._defined(el, idx, end, depth, implicit, little)
            el.end = pos

            if (tag & 0xFFFF) == 0 and length == 4 and vr in ("UL", "UN"):
                (value,) = struct.unpack_from(e + "I", self.buf, voff)
                glen = (group, pos + value, el.offset)
        if glen:
            self._group_length(glen, pos)
        return pos, False

    def _defined(self, el: Element, idx: int, end: int, depth: int, implicit: bool, little: bool) -> int:
        voff, vend = el.value_offset, el.value_offset + el.length
        if vend > end:
            # The bytes after this header cannot be trusted to belong to it.
            el.end = end
            self.note("length-overflow", f"{tag_str(el.tag)} declares {el.length:,} bytes but only "
                      f"{end - voff:,} remain in its container", voff, el.tag)
            raise _Desync
        if el.length % 2:
            self.note("odd-length", f"{tag_str(el.tag)} has odd length {el.length}", el.offset, el.tag)
        if el.vr == "SQ":
            try:
                self._sequence(idx, voff, vend, depth + 1, implicit, little, undefined=False)
            except _Desync:
                pass  # the sequence's declared length lets us resume right after it
        elif el.vr == "UN" and self._starts_with_item(voff, vend):
            self._tentative_sequence(el, idx, vend, depth)
        else:
            self.region(voff, vend, PADDING if el.tag == TRAILING_PADDING else VALUE)
        return vend

    def _undefined(self, el: Element, idx: int, end: int, depth: int, implicit: bool, little: bool) -> int:
        if el.vr in ("SQ", "UN"):
            if el.vr == "UN" and el.vr_source == "explicit":
                implicit, little = True, True  # PS3.5 6.2.2: such a UN holds an implicit VR LE sequence
            elif el.vr == "UN":
                el.vr, el.vr_source = "SQ", "inferred"
            return self._sequence(idx, el.value_offset, end, depth + 1, implicit, little, undefined=True)
        if el.tag == PIXEL_DATA and el.vr in ("OB", "OW"):
            return self._encapsulated(el, end, little)
        self.note("undefined-length-invalid", f"{tag_str(el.tag)} ({el.vr}) has undefined length, which only "
                  "sequences and encapsulated Pixel Data may use", el.value_offset, el.tag)
        raise _Desync

    # -- sequences ----------------------------------------------------------------

    def _sequence(self, parent: int, pos: int, end: int, depth: int, implicit: bool, little: bool,
                  *, undefined: bool) -> int:
        if depth > self.limits.max_depth:
            self.note("max-depth", f"sequences nest deeper than {self.limits.max_depth} levels", pos)
            raise _Desync
        fmt = "<HHI" if little else ">HHI"
        while pos < end:
            if pos + 8 > end:
                self.note("truncated-header", f"{end - pos} bytes remain in a sequence, too few for an item", pos)
                raise _Desync
            group, elem, length = struct.unpack_from(fmt, self.buf, pos)
            tag = group << 16 | elem
            if tag == SEQ_DELIM:
                self.region(pos, pos + 8, HEADER)
                if length:
                    self.note("delimiter-length", f"Sequence Delimitation Item has length {length}, not 0", pos, tag)
                if not undefined:
                    self.note("unexpected-delimiter",
                              "Sequence Delimitation Item inside a defined-length sequence", pos, tag)
                return pos + 8
            if tag != ITEM:
                self.note("bad-sequence-item", f"expected an Item inside the sequence but found {tag_str(tag)}",
                          pos, tag)
                raise _Desync
            self.admit(pos, tag)
            start = pos + 8  # the item's content; its end is known once the content is parsed
            item = Element(ITEM, "", "structural", pos, start, length, start, depth, parent, little, self.domain)
            item_idx = len(self.elements)
            self.elements.append(item)
            self.region(pos, pos + 8, HEADER)
            if length == UNDEFINED:
                pos, closed = self.dataset(pos + 8, end, depth, item_idx, implicit, little, in_item=True)
                if not closed:
                    self.note("missing-item-delimiter", "undefined-length item runs to the end of its container",
                              item.offset, ITEM)
            else:
                item_end = pos + 8 + length
                if item_end > end:
                    item.end = end
                    self.note("length-overflow", f"Item declares {length:,} bytes but only {end - pos - 8:,} "
                              "remain in its sequence", pos + 8, ITEM)
                    raise _Desync
                try:
                    self.dataset(pos + 8, item_end, depth, item_idx, implicit, little)
                except _Desync:
                    pass  # resume at the item's declared end
                pos = item_end
            item.end = pos
        if undefined:
            self.note("missing-sequence-delimiter", "undefined-length sequence runs to the end of its container",
                      pos, SEQ_DELIM)
        return pos

    def _starts_with_item(self, voff: int, vend: int) -> bool:
        if vend - voff < 8:
            return False  # pragma: no mutate (equivalent: the tentative parse rejects it)
        group, elem, length = struct.unpack_from("<HHI", self.buf, voff)
        # A pre-filter only: the tentative parse validates everything again and rolls back.
        is_item = group == 0xFFFE and elem == 0xE000  # pragma: no mutate (equivalent: pre-filter)
        fits = length == UNDEFINED or voff + 8 + length <= vend  # pragma: no mutate (equivalent: pre-filter)
        return bool(is_item and fits)  # pragma: no mutate (equivalent: pre-filter)

    def _tentative_sequence(self, el: Element, idx: int, vend: int, depth: int) -> None:
        """A value of unknown VR that starts with an Item tag is probably a sequence (encoded
        implicit VR LE, PS3.5 6.2.2). Parse it as one, and roll back unless it parses cleanly."""
        marks = len(self.anomalies), len(self.elements), len(self.regions)
        tally = self.tally
        saved = tally.total, Counter(tally.counts), dict(tally.first_suppressed)
        try:
            ok = self._sequence(idx, el.value_offset, vend, depth + 1, True, True, undefined=False) == vend
        except _Desync:
            ok = False  # pragma: no mutate (equivalent: a desync always records an anomaly)
        if ok and tally.total == saved[0]:  # counts suppressed anomalies too
            el.vr, el.vr_source = "SQ", "inferred"
            return
        del self.anomalies[marks[0]:], self.elements[marks[1]:], self.regions[marks[2]:]
        tally.total, tally.counts, tally.first_suppressed = saved
        self.region(el.value_offset, vend, VALUE)

    # -- encapsulated pixel data ---------------------------------------------------

    def _encapsulated(self, el: Element, end: int, little: bool) -> int:
        """Fragments of compressed frames: Item(Basic Offset Table), Item(fragment)..., delimiter."""
        fmt = "<HHI" if little else ">HHI"
        pos = el.value_offset
        el.fragments = []
        bot: tuple[int, int] | None = None
        item_offsets: list[int] = []
        while True:
            if pos + 8 > end:
                self.note("unterminated-pixel-data",
                          "encapsulated Pixel Data ends without a Sequence Delimitation Item", pos, el.tag)
                if pos < end:  # pragma: no mutate (equivalent: at the end, stopping and returning agree)
                    raise _Desync
                return pos
            group, elem, length = struct.unpack_from(fmt, self.buf, pos)
            tag = group << 16 | elem
            if tag == SEQ_DELIM:
                self.region(pos, pos + 8, HEADER)
                if length:
                    self.note("delimiter-length", f"Sequence Delimitation Item has length {length}, not 0", pos, tag)
                if bot:
                    self._check_offset_table(el, bot, item_offsets, little)
                return pos + 8
            if tag != ITEM:
                self.note("bad-fragment-item", f"expected a fragment Item in encapsulated Pixel Data but found "
                          f"{tag_str(tag)}", pos, tag)
                raise _Desync
            if length == UNDEFINED:
                self.note("undefined-fragment-length", "Pixel Data fragment has undefined length", pos, tag)
                raise _Desync
            self.region(pos, pos + 8, HEADER)
            value_end = pos + 8 + length
            if value_end > end:
                self.note("length-overflow", f"fragment declares {length:,} bytes but only {end - pos - 8:,} remain",
                          pos + 8, el.tag)
                raise _Desync
            if length % 2:
                self.note("odd-length", f"Pixel Data fragment has odd length {length}", pos, el.tag)
            self.region(pos + 8, value_end, VALUE)
            if bot is None:
                bot = (pos + 8, value_end)
            else:
                el.fragments.append((pos + 8, length))
                item_offsets.append(pos)
            pos = value_end

    def _check_offset_table(self, el: Element, bot: tuple[int, int], item_offsets: list[int], little: bool) -> None:
        start, end = bot
        if start == end:
            return
        if (end - start) % 4:
            self.note("bad-offset-table", "Basic Offset Table length is not a multiple of 4", start, el.tag)
            return
        n = (end - start) // 4
        offsets = struct.unpack_from(f"{'<' if little else '>'}{n}I", self.buf, start)
        # Offsets are relative to the first byte of the first fragment's Item tag (PS3.5 A.4).
        valid = {offset - end for offset in item_offsets}
        bad = sum(offset not in valid for offset in offsets)
        if bad or list(offsets) != sorted(offsets) or offsets[0] != 0:
            self.note("bad-offset-table", f"{bad} of {n} Basic Offset Table entries do not point at a fragment",
                      start, el.tag)
        else:
            el.offset_table = list(offsets)  # only a table that checks out is allowed to define frames

    # -- consistency checks ---------------------------------------------------------

    def _check_vr(self, el: Element) -> None:
        if el.vr_source == "explicit":
            allowed = dictionary.allowed_vrs(el.tag)
            if allowed and el.vr not in allowed:
                self.note("vr-mismatch", f"{dictionary.keyword(el.tag)} {tag_str(el.tag)} is encoded as {el.vr}; "
                          f"the standard requires {'/'.join(allowed)}", el.offset, el.tag)
        size = _FIXED_SIZE.get(el.vr)
        if size and el.length != UNDEFINED and el.length % size:
            self.note("vr-length-mismatch", f"{tag_str(el.tag)} ({el.vr}) has length {el.length}, "
                      f"not a multiple of {size}", el.offset, el.tag)

    def _group_length(self, glen: tuple[int, int, int], actual: int) -> None:
        group, expected, offset = glen
        if expected != actual:
            code = "meta-group-length-mismatch" if group == 0x0002 else "group-length-mismatch"
            self.note(code, f"group {group:04X} length says the group ends at {expected:#x}, but it actually "
                      f"ends at {actual:#x}", offset, group << 16)

    # -- transfer syntax ---------------------------------------------------------------

    def transfer_syntax(self) -> str | None:
        for el in self.elements:
            if el.tag == TRANSFER_SYNTAX and el.depth == 0:
                return bytes(self.buf[el.value_offset : el.end]).rstrip(b"\x00 ").decode("ascii", "replace")
        return None

    def sniff(self, pos: int, syntax: Syntax) -> tuple[bool, bool]:
        """Check the declared encoding against the first dataset element. Lenient readers
        silently switch when they disagree and strict ones fail, so a mismatch is itself a finding."""
        declared = (syntax.implicit, syntax.little)
        if self._plausible(pos, *declared) and not (syntax.implicit and self._clearly_explicit(pos)):
            return declared
        for alt in _ENCODINGS:
            if alt != declared and self._plausible(pos, *alt):
                self.note("transfer-syntax-mismatch", f"File Meta declares {syntax.name}, but the dataset is "
                          f"encoded as {_ENCODINGS[alt]}", pos)
                return alt
        return declared

    def detect(self, pos: int) -> tuple[bool, bool]:
        """Encoding of a dataset that declares none. Valid VR bytes are strong evidence, so both
        explicit encodings are tried first; otherwise implicit VR little endian, the historical
        default (ACR-NEMA and the DICOM default transfer syntax), plausible or not."""
        for encoding in ((False, True), (False, False)):
            if self._plausible(pos, *encoding):
                return encoding
        return True, True

    def _plausible(self, pos: int, implicit: bool, little: bool) -> bool:
        if pos + 8 > self.size:
            return False
        e = "<" if little else ">"
        group, _ = struct.unpack_from(e + "HH", self.buf, pos)
        if not 0x0004 <= group < 0xFFFE:
            return False
        if implicit:
            (length,) = struct.unpack_from(e + "I", self.buf, pos + 4)
            return bool(length == UNDEFINED or pos + 8 + length <= self.size)
        vr = bytes(self.buf[pos + 4 : pos + 6])
        if vr not in _VALID_VRS:
            return False
        if vr in _LONG_VRS:
            if pos + 12 > self.size:
                return False
            (length,) = struct.unpack_from(e + "I", self.buf, pos + 8)
            return bool(length == UNDEFINED or pos + 12 + length <= self.size)
        (length,) = struct.unpack_from(e + "H", self.buf, pos + 6)
        return bool(pos + 8 + length <= self.size)

    def _clearly_explicit(self, pos: int) -> bool:
        """Implicit data whose 'length' bytes spell the dictionary VR of the tag is really explicit."""
        group, elem = struct.unpack_from("<HH", self.buf, pos)
        expected = dictionary.vr(group << 16 | elem)
        return expected is not None and bytes(self.buf[pos + 4 : pos + 6]) == expected.encode()

    # -- deflate -----------------------------------------------------------------------

    def inflate(self, pos: int) -> bytes | None:
        d = zlib.decompressobj(-15)  # raw deflate, no zlib header (PS3.5 A.5)
        try:
            with memoryview(self.buf) as view, view[pos:] as stream:
                data = d.decompress(stream, self.limits.max_inflated)
        except zlib.error as exc:
            self.note("deflate-error", f"the deflated dataset is corrupt ({exc})", pos)
            return None
        if d.unconsumed_tail:
            self.note("deflate-bomb", f"the dataset inflates past the {self.limits.max_inflated:,}-byte limit", pos)
            self.region(pos, self.size, DEFLATE)
        elif not d.eof:
            self.note("deflate-truncated", "the deflate stream ends before its final block", pos)
            self.region(pos, self.size, DEFLATE)
        else:
            # Anything after the end of the deflate stream is left unexplained on purpose.
            self.region(pos, self.size - len(d.unused_data), DEFLATE)
        return data


def looks_like_dataset(buf: Buffer) -> bool:
    """Is `buf` a DICOM dataset without a Part 10 header?

    Strict enough that ordinary files never qualify: the first element must belong
    to group 0002 or 0008 (where every real dataset starts) and the first three
    top-level elements must parse cleanly in ascending order. Random data passes
    with a probability far below one in a billion.
    """
    head = bytes(buf[:4096])  # pragma: no mutate (tuning)
    for implicit, little in ((False, True), (True, True), (False, False)):
        if len(head) < 8 or struct.unpack_from("<H" if little else ">H", head, 0)[0] not in (0x0002, 0x0008):
            continue
        anomalies: list[Anomaly] = []
        elements: list[Element] = []
        # The trial parse is the test: a wrong encoding fails on the first element.
        trial = _Parser(head, Limits(max_elements=64),  # pragma: no mutate (tuning)
                        "file", anomalies, elements, _Tally())
        try:
            trial.dataset(0, len(head), 0, None, implicit, little)
        except _Desync:
            pass
        first_problem = min((a.offset for a in anomalies), default=len(head))
        clean = [el for el in elements if el.depth == 0 and el.end <= first_problem]
        if len(clean) >= 3 or (clean and clean[-1].end == len(buf)):
            return True
    return False
