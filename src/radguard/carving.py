"""Budgeted search for files embedded anywhere in a buffer.

The whole buffer is searched once, with one regular expression covering every
signature, and every consumer (unexplained regions, pixel slack, padding,
element values, codestreams) asks the resulting index for matches inside its
own byte range.

Work is bounded per buffer, and running out of budget is *reported*, never
silent. Without that rule a fixed cap is an evasion primitive: pad a file with
a few thousand decoy "MZ" bytes and the real executable behind them is never
examined. Here each magic gets a fair share of the candidate budget; a magic
that exhausts its share is dropped from the pattern (so a flood cannot stall
the scan or starve other signatures) and the flood itself becomes a finding.
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field

from radguard.dicom.model import Buffer
from radguard.signatures import SIGNATURES, Match, Signature


@dataclass(frozen=True)
class Budget:
    max_bytes: int = 1 << 30  # bytes of a buffer searched; pragma: no mutate (tuning)
    max_candidates: int = 1_000_000  # raw magic hits examined, split fairly across magics; pragma: no mutate (tuning)
    max_matches: int = 10_000  # validated matches kept; pragma: no mutate (tuning)


@dataclass(frozen=True)
class Exhaustion:
    reason: str  # "size": the buffer is larger than the window; "flood"/"matches": adversarial
    offset: int  # first byte that was not fully examined
    detail: str


@dataclass
class MatchIndex:
    matches: list[Match] = field(default_factory=list)
    exhausted: list[Exhaustion] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._offsets = [m.offset for m in self.matches]

    def within(self, start: int, end: int) -> list[Match]:
        lo = bisect.bisect_left(self._offsets, start)
        hi = bisect.bisect_left(self._offsets, end)
        return self.matches[lo:hi]


def carve(buf: Buffer, budget: Budget = Budget()) -> MatchIndex:
    end = min(len(buf), budget.max_bytes)
    exhausted: list[Exhaustion] = []
    if end < len(buf):
        exhausted.append(Exhaustion("size", end, f"only the first {end:,} of {len(buf):,} bytes were searched"))

    owners: dict[bytes, Signature] = {m: sig for sig in SIGNATURES for m in sig.scan_magics}
    share = max(1, budget.max_candidates // len(owners))
    seen = dict.fromkeys(owners, 0)
    # Longest first, so no magic could shadow a longer one.
    active = sorted(owners, key=len, reverse=True)  # pragma: no mutate (equivalent: no magic prefixes another)
    pattern = _compile(active)
    matches: list[Match] = []
    pos = 0
    while pattern is not None:
        hit = pattern.search(buf, pos, end)
        if hit is None:
            break
        magic = hit.group()
        seen[magic] += 1
        if seen[magic] > share:
            sig = owners[magic]
            exhausted.append(Exhaustion("flood", hit.start(), f"more than {share:,} candidate {sig.label} "
                                        f"signatures ({magic!r}); the file is built to exhaust analysis, and that "
                                        "signature was not searched for after this point"))
            active.remove(magic)
            pattern = _compile(active)
            pos = hit.start()  # rescan from here for every other signature
            continue
        sig = owners[magic]
        detail = sig.validate(buf, hit.start()) if sig.validate else ""
        if detail is not None:
            if len(matches) == budget.max_matches:  # this is match max+1: only now is "more than" true
                exhausted.append(Exhaustion("matches", hit.start(), f"more than {budget.max_matches:,} embedded "
                                            "files; the remainder of the buffer was not searched"))
                break
            matches.append(Match(hit.start(), sig, detail))
        pos = hit.start() + 1  # pragma: no mutate (equivalent: no magic overlaps another)
    return MatchIndex(matches, exhausted)


def _compile(magics: list[bytes]) -> re.Pattern[bytes] | None:
    return re.compile(b"|".join(re.escape(m) for m in magics)) if magics else None
