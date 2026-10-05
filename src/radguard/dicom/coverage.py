"""Byte-coverage accounting: which bytes the DICOM grammar explains, and which it doesn't.

A conforming Part 10 file is fully explained: preamble, magic, then a tree of
element headers and values. Any byte left over sits outside the structure
every DICOM reader walks, which makes it the natural place to hide a payload.
"""

from __future__ import annotations

from collections.abc import Iterable

from radguard.dicom.model import KINDS, Region


def gaps(regions: Iterable[Region], size: int) -> list[tuple[int, int]]:
    """Unexplained [start, end) ranges in a buffer of `size` bytes."""
    out = []
    cursor = 0
    for start, end, _ in sorted(regions):
        if start > cursor:
            out.append((cursor, start))
        cursor = max(cursor, end)
    if cursor < size:
        out.append((cursor, size))
    return out


def summary(regions: list[Region], size: int) -> dict[str, int]:
    totals = dict.fromkeys(KINDS, 0)
    for start, end, kind in regions:
        totals[kind] += end - start
    totals["unexplained"] = sum(end - start for start, end in gaps(regions, size))
    return totals
