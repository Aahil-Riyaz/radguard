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
