# Devlog

## 2026-10-04 (Day 1)

- Scaffolded the project: `src/` layout, zero runtime dependencies for L1, pytest, GitHub Actions CI.
- Implemented `preamble` check. Key details learned:
  - Part 10 = 128-byte preamble + `DICM` magic. PS3.10 §7.1 lets the preamble hold anything, and only explicitly mentions TIFF.
  - PE/DICOM polyglot: `MZ` sits at byte 0 and `e_lfanew` (offset 0x3C, still inside the preamble) points to `PE\0\0` placed *inside a DICOM element value* later in the file. Checking that pointer separates a real polyglot (critical) from a stray `MZ` (high).
  - ELF only needs its magic at byte 0, which is why ELFDICOM works against Linux-based devices.
- Next: parse the full dataset with pydicom and look for data hiding past the end of the dataset.
