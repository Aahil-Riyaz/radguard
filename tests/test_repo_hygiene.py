"""Our own source must not contain what we flag in other people's files.

Invisible and bidirectional-control characters in source code can make code
read differently from how it runs (Trojan Source, CVE-2021-42574). Python
files must be pure ASCII; every other text file must be free of controls and
invisible formatting characters.
"""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {".py", ".md", ".toml", ".yml", ".yaml", ".cfg", ".txt"}
INVISIBLE = {*range(0x00, 0x09), *range(0x0B, 0x0D), *range(0x0E, 0x20), *range(0x7F, 0xA0),
             *range(0x200B, 0x2010), *range(0x2028, 0x202F), *range(0x2060, 0x2065),
             *range(0x2066, 0x206A), 0xFEFF}


def tracked_text_files():
    for folder in ("src", "tests", "scripts", "docs", ".github"):
        yield from (p for p in (ROOT / folder).rglob("*") if p.suffix in TEXT_SUFFIXES)
    yield from (p for p in ROOT.glob("*") if p.suffix in TEXT_SUFFIXES)


@pytest.mark.parametrize("path", sorted(tracked_text_files()), ids=lambda p: str(p.relative_to(ROOT)))
def test_no_invisible_or_bidi_characters(path):
    text = path.read_text(encoding="utf-8")
    bad = [(n, f"U+{ord(c):04X}") for n, line in enumerate(text.split("\n"), 1)
           for c in line.rstrip("\r") if ord(c) in INVISIBLE]
    assert not bad, f"{path.name}: invisible characters at {bad[:5]}"
    if path.suffix == ".py":
        assert text.isascii(), f"{path.name}: Python sources must be ASCII"
