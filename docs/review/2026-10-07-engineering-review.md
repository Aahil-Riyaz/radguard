# Engineering review, 2026-10-07

**Question:** a green CI badge only means the code passed the checks its author wrote. Is RadGuard actually correct, complete, and honest about what it does?

**Scope:** every module, the tests, the docs. Baseline: commit `e1d23e7` (190 tests, CI green).

## Method

| Technique | What it answers |
|---|---|
| Branch coverage (`coverage.py`) | Which code never runs under the tests? |
| Strict static typing (`mypy --strict`) | Are types consistent everywhere, including the paths tests miss? |
| Mutation testing (`scripts/mutation_test.py`) | If a line were wrong, would any test fail? |
| Line-by-line review | Fail-open behaviour, blind spots, spec conformance, docs that no longer match the code |

Mutation testing is the strongest of these. Coverage only proves a line *ran*. The mutation tester changes the code one small step at a time (flips `<` to `<=`, `and` to `or`, `+` to `-`, bumps a constant, deletes a `raise`) and runs the full suite against each change in an isolated copy of the repository. A change that no test notices "survives", and each survivor is either a missing test or a provably equivalent change.

## Findings

| ID | Severity | Finding | Fix |
|---|---|---|---|
| ER-01 | High | A scan that could not read some files still exited 0 ("clean"), so CI gates passed unscanned files | Exit status 3, "scan incomplete", which takes precedence over findings; JSON `complete: false` |
| ER-02 | High | Unreadable directories vanished from scans: `os.walk` ignores errors by default | Reported as errors (and so exit 3) |
| ER-03 | High | DICOM datasets without the 128-byte header were skipped as "not DICOM". pydicom reads them with `force=True` | Bare-dataset parsing, with a strict detector |
| ER-04 | Medium | Compressed frames were grouped by heuristic even when a valid Basic Offset Table defines them (PS3.5 A.4) | A valid table is authoritative; an invalid one is never trusted |
| ER-05 | Medium | Conflicting image dimensions (e.g. two different Rows values) were not flagged: RadGuard sized the image from the first copy, pydicom from the last | `pixels.ambiguous-geometry` (high) |
| ER-06 | Low | The JPEG walker accepted `FF 00` as a marker outside entropy-coded data | Reported as a malformed codestream |
| ER-07 | Low | Every file up to 64 MiB was read in full before deciding whether it was DICOM | Decided from the first 4 KiB |
| ER-08 | Low | Symbolic links to directories were silently not followed | Reported as notes |
| ER-09 | Low | No type for the shared buffer: `FileContext` declared `bytes` but received `mmap`; 44 strict-typing errors | `Buffer` type; `mypy --strict` clean and enforced in CI |
| ER-10 | Info | Docs drift: "files are memory-mapped, never copied" stopped being true with the RG-04 fix | Docs corrected; exit codes documented |
| ER-11 | Info | JSON output carried no tool version or schema version | Added `tool`, `schema_version`, `complete` |

### ER-03 in detail

Reproduced before fixing: a bare dataset (no preamble, no `DICM`, no File Meta) ending in an executable.

```
pydicom force=True reads it: Rows = 8 Modality = CT
RadGuard today: is_dicom = False | findings = 0
```

After the fix the same file produces `structure.no-part10-header` and a critical `structure.hidden-payload`. The detector is strict so ordinary files never qualify: the first element must be in group 0002 or 0008, and the first three top-level elements must parse cleanly in ascending order. 2,000 random buffers that already begin with the right group bytes are all rejected (`tests/test_scanner.py`).

## Measurements

| Metric | Before | After |
|---|---|---|
| Tests | 190 | 615 (612 run on Windows; 3 need POSIX features and run in Linux CI) |
| Branch coverage | 94% | 98% (the remainder is mostly race-condition branches that cannot be produced deterministically) |
| `mypy --strict` errors | 44 | 0 |
| Anomaly rules with a test that triggers them | not measured | 33 / 33 (enforced by a completeness test) |
| Example files whose documented findings are pinned | 0 | 5 / 5, plus byte-for-byte reproducibility of examples and figure |
| Mutation score | not measured | 100% (918 of 918 mutants killed; 63 lines exempt, each with a stated reason) |

## Mutation testing results

Three runs over 14 modules, 12 parallel workers, about 16 minutes each:

| Run | Killed | Score | Notes |
|---|---|---|---|
| 1 | 723 / 945 | 76.5% (invalid) | The parser scored a fake 100%: one test read `parser.py` with a regex that expected double quotes, and every mutant is rewritten with `ast.unparse`, which writes single quotes, so that test failed for every parser mutant whether or not the mutation was caught |
| 2 | 803 / 1004 | 80.0% | Harness fixed (see below), first round of edge tests, private-data check added |
| 3 | 905 / 922 | **98.2%** | Second round of edge tests; equivalent mutants exempted with reasons |

Per module, run 3:

| Module | Killed | Score |
|---|---|---|
| `codecs.py`, `carving.py`, `signatures.py`, `output.py` | 232 / 232 | 100% |
| `checks/structure.py`, `pixels.py`, `codestream.py`, `values.py`, `preamble.py` | 190 / 190 | 100% |
| `dicom/values.py` | 21 / 21 | 100% |
| `dicom/parser.py` | 346 / 359 | 96.4% |
| `checks/private.py` | 63 / 64 | 98.4% |
| `scanner.py` | 24 / 25 | 96.0% |
| `dicom/paths.py` | 29 / 31 | 93.5% |

**The harness checks itself.** Before mutating anything, it rewrites every target file with `ast.unparse` *without* changing it and runs the suite. If that fails, some test depends on source formatting, and the run aborts instead of reporting fake kills. This self-check caught the run 1 problem and, later, a new line-length rule in the hygiene test (style tests are now excluded from mutation runs, since mutants change formatting by construction).

**What the survivors exposed:**
- **A real bug:** with `max_matches = N`, finding exactly N embedded files reported "more than N", because the limit was checked after appending instead of before.
- **Dead code:** `0 < e_lfanew` in `pe_header` could never change a result; two other guards were redundant with the operations they guarded.
- **A tautological test:** the ZIP method test iterated over the module's own constant, so a typo in the module changed the expected values too.
- **Missing exact-edge tests** for the output sanitiser's ranges, carving budgets, every signature validator field, codec segment limits, slack and gap severity thresholds, and the parser's plausibility checks.
- **Equivalent mutants**, which are exempted with `# pragma: no mutate (reason)`: tuning constants, display truncation, optimisation pre-filters whose work is repeated by a later step, and counters that are only compared for equality.

**Closing the last 17 survivors.** Two were resolved by code changes: an Item's start offset now comes from one variable, and encoding detection tries both explicit forms (whose VR bytes are strong evidence) before falling back to implicit VR. The rest got one edge test each: `(gggg,0100)` is not a creator, `(gggg,1000)` is the first data element, a long-VR header of exactly 12 bytes, a Basic Offset Table at an odd file offset, big-endian bare-dataset detection, pixel checks inside a deflated dataset, exact anomaly lists after an item overflow and after unterminated pixel data, and `is_dicom` on directory errors. A targeted run 4 over the four affected modules killed 474 of 475. The last survivor (a sequence delimiter's region claiming 9 bytes instead of 8, overlapping the next element by one byte) is killed by a test that regions never overlap after a delimiter, verified by applying that exact mutant.

**Final: 918 of 918 mutants killed (100%)** across 14 modules, with 63 lines exempt as equivalent mutants, each with its reason in the source.

## Process notes

- Shell heredocs in this environment collapse `\\` into `\`. Twice that silently turned intended escape sequences into raw bytes or into different escapes, and one test passed by coincidence. All source edits now go through the file tool, and `tests/test_repo_hygiene.py` compiles every Python file with warnings as errors, so an invalid escape fails the build.
- Several fixes were reproduced against the baseline before being made, so each "before" in this report is observed rather than assumed.
