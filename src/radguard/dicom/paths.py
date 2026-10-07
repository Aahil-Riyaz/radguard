"""Human-readable locations: "(0008,1140) item 2 > (0029,1010) Private [SIEMENS CSA HEADER]"."""

from __future__ import annotations

import bisect
from collections import Counter

from radguard.dicom import dictionary
from radguard.dicom.model import ITEM, TRAILING_PADDING, Buffer, Element, ParsedFile, tag_str
from radguard.signatures import printable

CreatorKey = tuple[str, "int | None", int, int]  # (domain, parent, group, block)


def private_creators(parsed: ParsedFile, file_buf: Buffer) -> dict[CreatorKey, str]:
    """Private Creator values by the block they reserve, per dataset (PS3.5 7.8.1)."""
    creators: dict[CreatorKey, str] = {}
    for el in parsed.elements:
        group, elem = el.tag >> 16, el.tag & 0xFFFF
        if group % 2 and 0x0010 <= elem <= 0x00FF:  # odd groups only, so never the Item tag (FFFE)
            raw = bytes(parsed.buffer(el.domain, file_buf)[el.value_offset : el.end]).rstrip(b" \x00")
            text = printable(raw, 48)  # attacker-controlled; pragma: no mutate (display limit)
            creators.setdefault((el.domain, el.parent, group, elem), text)
    return creators


def name(el: Element, creators: dict[CreatorKey, str]) -> str:
    """Keyword for an element; private data elements also name the creator that owns them."""
    keyword = dictionary.keyword(el.tag)
    group, elem = el.tag >> 16, el.tag & 0xFFFF
    if group % 2 and elem >= 0x1000:
        owner = creators.get((el.domain, el.parent, group, elem >> 8))
        return f"{keyword} [{owner if owner is not None else 'no creator'}]"
    return keyword


class Locator:
    """Maps offsets to the leaf element whose value contains them, and elements to paths."""

    def __init__(self, parsed: ParsedFile, domain: str, file_buf: Buffer):
        self.elements = parsed.elements
        self.creators = private_creators(parsed, file_buf)
        ordinals: dict[int, int] = {}
        counter: Counter[int | None] = Counter()
        spans: list[tuple[int, int, int]] = []
        for idx, el in enumerate(parsed.elements):
            if el.tag == ITEM:
                counter[el.parent] += 1
                ordinals[idx] = counter[el.parent]
            elif el.domain == domain and el.vr != "SQ" and el.fragments is None and el.tag != TRAILING_PADDING:
                spans.append((el.value_offset, el.end, idx))
        spans.sort()
        self._ordinals = ordinals
        self._starts = [s for s, _, _ in spans]
        self._spans = spans

    def element_at(self, offset: int) -> Element | None:
        """The leaf element whose value contains `offset`, if any."""
        i = bisect.bisect_right(self._starts, offset) - 1
        if i >= 0:
            start, end, idx = self._spans[i]
            if start <= offset < end:
                return self.elements[idx]
        return None

    def path(self, el: Element) -> str:
        parts = [f"{tag_str(el.tag)} {name(el, self.creators)}"]
        parent = el.parent
        while parent is not None:  # parent chain: element -> item -> sequence -> item ...
            item = self.elements[parent]
            seq = self.elements[item.parent] if item.parent is not None else None
            if seq is None:
                break
            parts.append(f"{tag_str(seq.tag)} item {self._ordinals.get(parent, '?')}")
            parent = seq.parent
        return " > ".join(reversed(parts))
