"""`radguard map`: a byte-level map of one DICOM file, hidden regions included."""

from __future__ import annotations

from collections import Counter

from radguard import signatures
from radguard.carving import MatchIndex, carve
from radguard.dicom import ParsedFile, coverage, dictionary, paths, values
from radguard.dicom.model import ITEM, PIXEL_DATA, Buffer, Element, Region, tag_str


def render(path: str, buf: Buffer, parsed: ParsedFile, *, max_depth: int | None = None,
           show_phi: bool = False) -> list[str]:
    lines = [path, f"{parsed.size:,} bytes, {parsed.syntax.name}", "", f"{'offset':>8}  {'length':>10}  structure"]
    creators = paths.private_creators(parsed, buf)  # resolved against the file buffer, for every domain
    lines += _domain(buf, parsed, "file", parsed.regions, parsed.size, carve(buf), creators, max_depth, show_phi)
    if parsed.inflated is not None:
        lines += ["", f"inflated dataset: {len(parsed.inflated):,} bytes (offsets below are within it)"]
        lines += _domain(parsed.inflated, parsed, "inflated", parsed.inflated_regions,
                         len(parsed.inflated), carve(parsed.inflated), creators, max_depth, show_phi)
    lines += ["", _coverage_line(parsed.regions, parsed.size)]
    return lines


def _domain(buf: Buffer, parsed: ParsedFile, domain: str, regions: list[Region], size: int, index: MatchIndex,
            creators: dict[paths.CreatorKey, str], max_depth: int | None, show_phi: bool) -> list[str]:
    rows: list[tuple[int, int, str]] = []  # (offset, order at that offset, line)
    if domain == "file" and parsed.part10:
        pre = bytes(buf[:128])
        state = "all zero" if not any(pre) else signatures.describe(buf, 0, 128)
        rows.append((0, 0, f"{0:08X}  {128:>10}  Preamble ({state})"))
        rows.append((128, 0, f"{128:08X}  {4:>10}  'DICM' magic"))

    children = Counter(el.parent for el in parsed.elements if el.tag == ITEM)
    item_numbers: Counter[int | None] = Counter()
    for idx, el in enumerate(parsed.elements):
        if el.domain != domain or (max_depth is not None and el.depth > max_depth):
            continue
        if el.tag == ITEM:
            item_numbers[el.parent] += 1
            label = f"Item #{item_numbers[el.parent]}"
        else:
            label = f"{tag_str(el.tag)} {el.vr:<2}  {paths.name(el, creators)}"
        indent = "  " * (2 * el.depth - (el.tag == ITEM))
        length = "undefined" if el.undefined else f"{el.length:,}"
        value = _value(buf, el, children.get(idx, 0), show_phi)
        rows.append((el.offset, 1, f"{el.offset:08X}  {length:>10}  {indent}{label:<44} {value}".rstrip()))

    for a in parsed.anomalies:
        if a.domain == domain:
            rows.append((a.offset, 2, f"{a.offset:08X}  {'':>10}  !! {a.code}: {a.message}"))
    for start, end in coverage.gaps(regions, size):
        hits = index.within(start, end)
        listed = ", ".join(f"{m.signature.label} at {m.offset:#x}" for m in hits[:3])
        found = f"contains {listed}; " if hits else ""
        described = signatures.describe(buf, start, end)
        rows.append((start, 3, f"{start:08X}  {end - start:>10,}  ?? UNEXPLAINED  {found}{described}"))

    rows.sort(key=lambda r: (r[0], r[1]))
    return [line for _, _, line in rows]


def _value(buf: Buffer, el: Element, n_items: int, show_phi: bool) -> str:
    if el.tag == ITEM:
        return ""
    if el.vr == "SQ":
        return f"{n_items} item(s)" + (" [VR inferred]" if el.vr_source == "inferred" else "")
    if el.tag == PIXEL_DATA:
        if el.fragments is not None:
            return f"{len(el.fragments)} fragment(s), encapsulated"
        return f"<{el.end - el.value_offset:,} bytes of pixels>"
    if el.tag in dictionary.PHI_TAGS and not show_phi:
        return f"<redacted, {el.end - el.value_offset} bytes>"
    return values.text(buf, el)


def _coverage_line(regions: list[Region], size: int) -> str:
    totals = coverage.summary(regions, size)
    explained = size - totals["unexplained"]
    parts = " | ".join(f"{kind} {count:,}" for kind, count in totals.items() if count)
    return f"coverage: {100 * explained / size:.2f}% of bytes explained by the DICOM structure  [{parts}]"
