# Devlog

## 2026-10-04 (Day 1)

- Scaffolded the project: `src/` layout, zero runtime dependencies for L1, pytest, GitHub Actions CI.
- Implemented `preamble` check. Key details learned:
  - Part 10 = 128-byte preamble + `DICM` magic. PS3.10 §7.1 lets the preamble hold anything, and only explicitly mentions TIFF.
  - PE/DICOM polyglot: `MZ` sits at byte 0 and `e_lfanew` (offset 0x3C, still inside the preamble) points to `PE\0\0` placed *inside a DICOM element value* later in the file. Checking that pointer separates a real polyglot (critical) from a stray `MZ` (high).
  - ELF only needs its magic at byte 0, which is why ELFDICOM works against Linux-based devices.
- Next: parse the full dataset with pydicom and look for data hiding past the end of the dataset.

## 2026-10-05 (Day 2)

**Built a DICOM parser from scratch instead of using pydicom.** Reason: a reader guesses past broken structure, and an attacker lives exactly where a reader guesses. Design: [docs/design/parser.md](design/parser.md).

- **Byte coverage.** Every byte is classified (preamble, magic, header, value, padding, deflate). Leftover bytes are "unexplained", and they get carved for embedded executables. This one idea catches appended payloads, data after a deflate stream and junk after a broken element, without writing a rule for each.
- **Recovery model.** On corruption the parser raises `_Desync` and resumes at the nearest container with a *defined length*. Undefined-length containers can't be resync points: their end is a delimiter inside content we no longer trust.
- **Lengths never claim bytes they can't own.** If an element's length overflows its container, its value stays unexplained. Otherwise appending a payload plus one huge length field would make the payload look legitimate.
- **Sequence inference with rollback.** Implicit VR and `UN` don't say what's a sequence. A value starting with an Item tag is parsed tentatively and rolled back unless the parse is clean, so no data dictionary is needed.
- **New checks:** hidden payloads, non-zero trailing padding, pixel slack and hidden frames, truncated pixels, 32-bit size overflow, encoding vs transfer syntax, 31 structural anomaly rules each with a "why it matters".
- **`radguard map`:** hex-offset view of every element, anomaly and unexplained region, plus a coverage percentage. Masks PHI by default.

**Verified against pydicom 3.0.2** (each is now a test in `tests/test_differential.py`):
- Duplicate Pixel Data: pydicom silently shows the *last* copy. Built `examples/two-scans-one-file.dcm`: clean lungs in copy 1, a nodule in copy 2.
- Pixel slack: pydicom does **not** drop extra bytes; it returns them as extra frames (`(2, 8, 8)` for a 1-frame header).
- Appended PE: pydicom invents attributes from it (`MZ` read as group `0x5A4D`). No warning.
- Wrong transfer syntax: pydicom switches encoding with a warning.
- Wrong meta group length: pydicom ignores it and scans by group.

**Testing:** 77 tests. Hypothesis fuzzing checks four invariants for any input (no exception; regions in bounds; no overlap; explained + unexplained == size). Deep run: 100,000 cases, 0 failures. Mutation check: planting a length-trusting bug is caught in ~1 s (`16777474 <= 258`).

**Learned:** the dangerous files aren't the malformed ones, they're the *ambiguous* ones. Every place two readers can disagree is a place to hide a second meaning.

Next (Day 3): carve every element value (OB/OW/UN/UT/private), encapsulated fragments and Encapsulated Document (0042,0011).

## 2026-10-06 (Day 3)

**Self-audit first.** RadGuard reads hostile files for a living, so RadGuard is a target. Threat model: the attacker controls the bytes, the file names, the directory layout and the timing. Goals: evade, crash or hang, exhaust, or attack the analyst through our output. Full report: [security/self-audit.md](security/self-audit.md). 9 findings, all fixed, each with a regression test named after its ID; the detection gaps were reproduced on yesterday's commit before fixing.

- **RG-01 (high):** Day 2's signature search silently stopped after 4,096 candidates per signature. 5,000 decoy `MZ` pairs in front of a real executable made it disappear (reproduced: `hidden-payload` became `unexplained-bytes`). Rebuilt as `carving.py`: one adaptive regex pass over the whole file, a fair candidate budget per signature, and a flooded signature is dropped from the pattern while the flood itself becomes a high finding. **Lesson: a budget must never turn into a blind spot. Running out of budget is evidence.**
- **RG-03 (high):** a named pipe in a scanned folder hung the scanner forever (`open()` waits for a writer). Fix: `stat` pre-filter, then `O_NONBLOCK` open and `fstat` on the descriptor actually read, so there is no race window.
- **RG-04:** memory-mapped files raise SIGBUS (uncatchable) if truncated mid-scan on POSIX. Files up to 64 MiB are now read privately.
- **RG-05:** file names could inject terminal escape sequences or bidi overrides (`gpj.exe` displayed as `exe.jpg`). Everything printed goes through `output.safe()`.
- **RG-06:** a 1.3 MB file produced 134,465 findings. Now capped per code and per check, with summaries.
- **RG-09:** yesterday's weak signatures gave 2 false positives per 16 MiB of random data; today's engine searches all pixel data, so that would be about 128 false alerts per GB. Structural validators per signature: 0.

**Value-level inspection.**
- Every attribute value is carved; findings give the exact path, e.g. `(0008,1140) item 2 > (0029,1010) Private`. Executables are critical anywhere; vendor XML or PDF in private tags is only low.
- Encapsulated documents: declared MIME type versus real content; executables inside.
- Executables stored as image pixels.
- **Codestream walkers** (`codecs.py`) for JPEG (T.81), JPEG-LS (T.87), JPEG 2000 (T.800) and RLE. They follow the marker structure to the frame's true end instead of searching for the first `FF D9`, which also occurs inside EXIF thumbnails and J2K comment segments. Findings: data after the end of a frame (including a second hidden image), frames that aren't the declared codec, malformed codestreams, undeclared frames.

**Process notes.**
- Measured before designing: one regex pass over 64 MB took 0.79 s against 1.23 s for 26 separate `find` passes.
- Windows Smart App Control started blocking Hypothesis's unsigned native extension. Rather than touch the policy, pinned the last pure-Python release (6.155.7) on Windows only.
- Caught in my own review before committing: a Python loop over every trailing byte (replaced with C-level `find`), a stale variable on an untested path (found by grep; pyflakes now runs locally and ruff in CI), and invisible Unicode characters that tooling had written into RadGuard's own sanitizer source. `tests/test_repo_hygiene.py` now fails the build on any invisible or bidi character in tracked files.

**Numbers:** 190 tests (189 run on Windows; the FIFO test is POSIX-only and runs in Linux CI). Deep fuzz: 150,000 cases across 6 targets (parser, every check, codec walkers), 0 failures.

Next (Day 4): private-tag analysis (creator blocks, oversized and high-entropy private values).

## 2026-10-07 (Day 4)

**A green badge only proves the code passed the checks I wrote, so I reviewed the project like a skeptical senior reviewer.** Full report: [review/2026-10-07-engineering-review.md](review/2026-10-07-engineering-review.md).

- **Fail-open bugs, fixed.** A scan that could not read some files still exited 0, so CI gates passed unscanned files. Unreadable directories vanished silently (`os.walk` ignores errors by default). DICOM data without the 128-byte header was skipped as "not DICOM", although pydicom reads it in force mode: reproduced with a header-less file ending in an executable, which RadGuard reported as clean. Now exit status 3 means "scan incomplete" and takes precedence over findings, directory errors are reported, and bare datasets are analysed.
- **Strict typing:** 44 `mypy --strict` errors to 0. The root cause was a missing type for the buffer every check reads (`bytes` for small files, `mmap` for large ones). Enforced in CI with a 90% coverage floor.
- **Mutation testing.** Built `scripts/mutation_test.py`, which makes one small change at a time and runs the suite against each. The first run gave the parser a fake 100% because one test depended on source formatting; the harness now checks itself before mutating and refuses to run if that happens. Real score went from 80.0% to **100%** (918 of 918), and the survivors exposed a real off-by-one in carving, dead code, and a test that compared a constant with itself.

**Private-data analysis.** Vendor blocks are checked against PS3.5 7.8 (orphan data, forbidden groups, malformed or duplicate creators), high-entropy blobs of unknown format are flagged, and zlib/gzip private values are **decompressed under strict budgets and searched**, because compression hides an executable from any signature search. Design: [design/private-data.md](design/private-data.md).

**Security review of my own first draft found three holes (RG-10 to RG-12):** `zlib` treats `max_length=0` as *unlimited*, so an exhausted budget would have inflated the next value without any cap; two bytes of fake zlib header let encrypted data skip the entropy check; and bytes after a valid compressed stream were never examined.

**Numbers:** 615 tests, 98% branch coverage, 100% mutation score (918/918), mypy strict clean.

**Learned:** a metric is only as honest as the tool measuring it. The mutation tester produced a convincing 100% that was entirely fake, and the fix was to make the tool verify its own preconditions before reporting anything.

Next (Day 5): SARIF output, so findings land in GitHub code scanning and SIEMs.
