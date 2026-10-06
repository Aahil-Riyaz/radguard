"""Human-readable locations for elements and bytes: "(0008,1140) item 2 > (0029,1010) Private"."""

from __future__ import annotations

import bisect
from collections import Counter

from radguard.dicom import dictionary
from radguard.dicom.model import ITEM, TRAILING_PADDING, Element, ParsedFile, tag_str


class Locator:
    """Maps offsets to the leaf element whose value contains them, and elements to paths."""

    def __init__(self, parsed: ParsedFile, domain: str):
        self.elements = parsed.elements
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
        parts = [f"{tag_str(el.tag)} {dictionary.keyword(el.tag)}"]
        parent = el.parent
        while parent is not None:  # parent chain: element -> item -> sequence -> item ...
            item = self.elements[parent]
            seq = self.elements[item.parent] if item.parent is not None else None
            if seq is None:
                break
            parts.append(f"{tag_str(seq.tag)} item {self._ordinals.get(parent, '?')}")
            parent = seq.parent
        return " > ".join(reversed(parts))
