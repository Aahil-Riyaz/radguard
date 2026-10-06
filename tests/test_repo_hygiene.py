"""Our own source must not contain what we flag in other people's files.

Invisible and bidirectional-control characters in source code can make code
read differently from how it runs (Trojan Source, CVE-2021-42574). Python
files must be pure ASCII; every other text file must be free of controls and
invisible formatting characters.
"""

import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {".py", ".md", ".toml", ".yml", ".yaml", ".cfg", ".txt"}
INVISIBLE = {*range(0x00, 0x09), *range(0x0B, 0x0D), *range(0x0E, 0x20), *range(0x7F, 0xA0),
             *range(0x200B, 0x2010), *range(0x2028, 0x202F), *range(0x2060, 0x2065),
             *range(0x2066, 0x206A), 0xFEFF}


def tracked_text_files():
    try:  # what the repository actually contains, not build output or local files
        names = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
        paths = [ROOT / name for name in names.splitlines()]
    except (OSError, subprocess.CalledProcessError):  # e.g. an exported tree without .git
        paths = [p for folder in ("src", "tests", "scripts", "docs", ".github") for p in (ROOT / folder).rglob("*")
                 if ".egg-info" not in str(p)] + list(ROOT.glob("*"))
    return [p for p in paths if p.suffix in TEXT_SUFFIXES and p.is_file()]


@pytest.mark.parametrize("path", sorted(tracked_text_files()), ids=lambda p: str(p.relative_to(ROOT)))
def test_no_invisible_or_bidi_characters(path):
    text = path.read_text(encoding="utf-8")
    bad = [(n, f"U+{ord(c):04X}") for n, line in enumerate(text.split("\n"), 1)
           for c in line.rstrip("\r") if ord(c) in INVISIBLE]
    assert not bad, f"{path.name}: invisible characters at {bad[:5]}"
    if path.suffix == ".py":
        assert text.isascii(), f"{path.name}: Python sources must be ASCII"
