# RadGuard self-audit, 2026-10-06

**Scope:** everything that touches attacker-controlled input: `scanner.py` (file system), `dicom/parser.py`, `carving.py`, `signatures.py`, `codecs.py`, every check, and the CLI's output path. Baseline: commit `b3567eb`.

**Result:** 9 findings (2 high, 4 medium, 3 low), all fixed, each pinned by a regression test in [`tests/test_hostile.py`](../../tests/test_hostile.py) named after its ID. Two further issues were caught in review of the new code before it was committed.

## Threat model

RadGuard exists to read hostile files, so the scanner itself is a target. The attacker controls:

- **file bytes:** every length, offset, count and string in the file;
- **file names:** including control and bidirectional-override characters;
- **the directory being scanned:** FIFOs, device files, symlinks, very large files;
- **timing:** files can change while they are being scanned.

The attacker's goals: **evade** detection, **crash or hang** the scanner (one bad file stops a whole archive sweep), **exhaust** CPU or memory, or **attack the analyst** through the scanner's own output.

## Method

1. Manual review of every read of attacker-controlled data, asking for each: what bounds it, what happens at the bound, and is reaching the bound visible?
2. Adversarial regression tests for each finding, including reproduction against the baseline commit where the finding is a detection gap.
3. Property-based fuzzing (Hypothesis): 6 targets, 400 cases each per run and 25,000 each (150,000 total) in deep mode, checking that parsing and every check terminate without raising and that byte accounting stays exact. The harness itself is mutation-tested: a planted length-trusting bug is caught in about a second.
4. Static analysis (pyflakes locally, ruff in CI).

## Findings

| ID | Severity | Finding | Status |
|---|---|---|---|
| RG-01 | High | Decoy flood evades embedded-file detection | Fixed |
| RG-02 | Medium | Silent search window per region | Fixed |
| RG-03 | High | Scanner hangs on a FIFO; device files are opened | Fixed |
| RG-04 | Medium | SIGBUS crash if a mapped file is truncated during a scan | Fixed (residual risk above 64 MiB) |
| RG-05 | Medium | Terminal escape and Trojan Source injection through output | Fixed |
| RG-06 | Medium | Unbounded anomalies and findings per file | Fixed |
| RG-07 | Low | Unvalidated depth limit could become a RecursionError | Fixed |
| RG-08 | Low | `BufferError` while unmapping would abort a directory scan | Fixed |
| RG-09 | Low | Weak anywhere-signatures produce false positives in pixel data | Fixed |

### RG-01 (High): decoy flood evades embedded-file detection

The baseline signature search examined at most 4,096 candidate hits per magic and then stopped, silently. Padding a file with 5,000 `MZ` byte pairs before a real executable made the executable invisible. Reproduced on `b3567eb`:

```
    0 decoys -> ['structure.hidden-payload']
 5000 decoys -> ['structure.unexplained-bytes']      <- executable no longer mentioned
```

**Fix:** `carving.py`, a single budgeted search over the whole buffer. Each magic gets a fair share of a per-file candidate budget. A magic that exhausts its share is removed from the search pattern, so the flood can neither stall the scan nor starve other signatures, and the exhaustion becomes a **high** finding (`structure.analysis-incomplete`, "File built to exhaust analysis"). Principle: *a budget must never turn into a blind spot; running out of budget is itself evidence.*

### RG-02 (Medium): silent search window per region

Unexplained regions were searched only within their first 64 MiB, without saying so. **Fix:** a single per-buffer window (1 GiB by default). Bytes beyond it are reported as a low finding ("File larger than the inspection window") with the exact offset where inspection stopped.

### RG-03 (High): scanner hangs on a FIFO; device files are opened

`open()` on a named pipe blocks until a writer appears, so one FIFO in a scanned directory hung the scan forever. Device files could be read endlessly (`/dev/zero`) or have side effects on open (tape devices rewind). **Fix:** a cheap `stat()` filters non-regular files without opening them. The authoritative check is `fstat()` on the descriptor actually read, opened with `O_NONBLOCK | O_NOCTTY`, so swapping the path for a FIFO between the two calls gains nothing (no TOCTOU window).

### RG-04 (Medium): SIGBUS if a mapped file is truncated mid-scan

Every file was memory-mapped. On POSIX, if another process truncates a mapped file, touching the vanished pages raises SIGBUS, which Python cannot catch: the process dies. Archives being written while they are scanned make this realistic. **Fix:** files up to 64 MiB (nearly every DICOM instance) are read into private memory, which cannot shrink; only larger files are mapped. **Residual risk:** a file over 64 MiB truncated during its own scan can still crash the process on POSIX. Windows is not affected, because it refuses to truncate a mapped file.

### RG-05 (Medium): output injection

File names and values derived from file contents were printed raw. A file named with ANSI escape sequences could clear or rewrite the analyst's terminal. A name containing U+202E (right-to-left override) displays `gpj.exe` as `exe.jpg` (Trojan Source, CVE-2021-42574). **Fix:** `output.safe()` escapes C0/C1 controls, DEL, zero-width characters, line separators and every bidi control. Every human-readable line passes through it. JSON output was already safe: `json.dumps` escapes controls, and `ensure_ascii` escapes all non-ASCII.

### RG-06 (Medium): unbounded anomalies and findings

Reproduced on `b3567eb`: a 1.3 MB file of tiny malformed elements produced **134,465 anomalies and 134,465 findings**, flooding memory, time and the report. **Fix:** the parser records 50 anomalies per code per file and summarises the rest. The scanner keeps 100 findings per check per file and adds one `scan.findings-suppressed` finding. Speculative parses (sequence inference) count suppressed anomalies too, so suppression cannot make a failed speculation look clean.

### RG-07 (Low): unvalidated depth limit

`Limits.max_depth` was not validated. Each nesting level costs three Python frames, so a caller-supplied limit produced a `RecursionError` instead of an anomaly (reproduced on `b3567eb` with `max_depth=400`). **Fix:** a validated ceiling of 128, tested with 178 levels of nesting.

### RG-08 (Low): `BufferError` aborts a directory scan

If any view into a memory map were still alive when it was closed, `mmap.close()` raises `BufferError`, which was not caught, so one file would abort the whole run. **Fix:** caught and reported for that file. The parser also releases its only views (deflate input) deterministically.

### RG-09 (Low): false positives from weak anywhere-signatures

Searching anywhere in a file needs more evidence per hit than matching at a fixed offset. The baseline used `#!/` (3 bytes) and unvalidated 4-byte magics: **2 false positives in 16 MiB of random data**, about 128 per GB. That is harmless when only searching unexplained bytes, but unacceptable once every value, pixel data included, is searched. **Fix:** structural validators per signature (PE header via `e_lfanew`, ELF `e_ident` and `e_type`, Mach-O CPU type, ZIP local-header fields, Java class version, interpreter path for scripts, PDF version). Result: 0 matches in 16 MiB of random data (test `test_rg09_*`).

## Caught in review before commit

- **Quadratic-style byte loop.** The first draft of the hidden-image search after a compressed frame looped over every trailing byte in Python, so a 100 MB tail meant 100 million iterations. Replaced with C-level `bytes.find`. All loops over attacker data now either run in C (`re`, `find`) or advance by at least one structure per iteration, with a cap (`codecs.MAX_SEGMENTS`).
- **Invisible characters in RadGuard's own source.** Tooling had written `\u` escapes in the output sanitiser and its tests as the literal invisible characters, including a U+2028 line separator inside a string literal. Python accepted it, but no reviewer could see it. The files were rewritten in pure ASCII, and `tests/test_repo_hygiene.py` now fails the build if any source file contains invisible or bidi characters.

## Verified not vulnerable

- **Regular-expression DoS:** every pattern is a literal alternation or a bounded character class; there are no nested quantifiers to backtrack on.
- **Symlink loops:** `os.walk` does not follow directory symlinks.
- **Decompression bombs:** inflation is capped (256 MiB) and reported.
- **Integer overflow:** not applicable in Python. RadGuard models 32-bit overflow only to warn about C/C++ decoders (`pixels.size-overflow`).
- **Writes and network:** RadGuard never writes to scanned paths and makes no network connections. The only file it writes is the report named with `--output`: written to a private temporary file beside it and renamed over it, so a reader never sees a partial report and an existing symlink at that path is replaced rather than followed.

## 2026-10-07: new code reviewed before commit

The day 4 private-data check decompresses attacker data, so it was reviewed against the same threat model before it was committed. Four issues were found in the first draft and fixed, each pinned by a test in `tests/test_private.py`:

| ID | Severity | Issue in the draft | Fix |
|---|---|---|---|
| RG-10 | High | When the per-file decompression budget reached zero, the next value was inflated with `max_length=0`, which Python's `zlib` treats as **no limit**: a full bypass of the bomb protection | A spent budget is reported and never passed to the inflater |
| RG-11 | Medium | Two bytes that look like a zlib header (`78 9C`) in front of encrypted data made the check try to inflate, fail, and skip the entropy test: evasion with two bytes | A value that does not inflate is judged as raw bytes |
| RG-12 | Medium | A tiny valid zlib stream followed by encrypted bytes inflated cleanly, and the trailing bytes were never examined | Bytes after the end of a compressed stream are reported (`private.data-after-stream`) |
| RG-13 | Low | The per-file budget was a dataclass default bound when the class was defined, so the module-level limit could not be changed | Read when each scan starts |

The engineering review the same day ([2026-10-07](../review/2026-10-07-engineering-review.md)) also found three fail-open gaps with security impact: scans that could not read some files exited 0, unreadable directories were skipped silently, and DICOM datasets without a Part 10 header were not analysed at all.

## 2026-10-09: reports and SARIF

Day 5 added SARIF output, which carries attacker-controlled text into GitHub code scanning and other viewers, so the whole output path was reviewed against the threat model: what can a hostile file *name* or file *content* do to the report and to the people and systems that read it? Four issues were found in existing code, each reproduced before fixing and pinned by a test in `tests/test_hostile.py`:

| ID | Severity | Issue | Fix |
|---|---|---|---|
| RG-14 | High | **A file name could abort the text report.** With output redirected (CI logs, `> report.txt`), Python encodes stdout in the Windows code page with `errors="strict"`. A legitimate Chinese file name raised `UnicodeEncodeError` halfway through: everything after it was lost, and the crash exited with status 1, the "findings" status. On Linux a name that is not valid UTF-8 did the same. Reproduced with a Chinese name and with an unpaired surrogate | Streams write unencodable characters as escapes; `safe()` also escapes surrogates |
| RG-15 | Medium | **A file name could invalidate the whole JSON report.** POSIX names that are not UTF-8, and NTFS names with unpaired surrogates, reach Python as lone surrogates, which `json.dumps` writes as `\udcff` escapes: valid for Python, rejected by strict parsers such as Rust's serde_json, so one planted file name could discard every finding in a SIEM pipeline | Every string in a JSON or SARIF report is made valid Unicode before serialising |
| RG-16 | Low | **An internal error looked like a verdict.** An uncaught exception exits with status 1, the "findings" status, so a crash while reporting could pass for an ordinary result | Any internal error, and a closed output pipe, exits 3 (incomplete) |
| RG-17 | Medium | **Git LFS pointers passed as clean.** A repository that stores DICOM files in Git LFS, checked out in CI without LFS, holds small text pointers in place of the images; RadGuard skipped them as "not DICOM" and the scan passed without seeing a single image | A Git LFS pointer is an error (the scan is incomplete), and the message says how to fetch the content |

The SARIF writer was designed against the same threat model from the start ([design](../design/sarif.md)):

- **Link injection.** SARIF viewers render `[text](target)` in a message as a link, GitHub may render messages as Markdown, and pull request annotations are visible to anyone who can read the repository. A vendor name such as `[Download the fixed viewer](https://...)` must stay text. Escaping brackets as the spec describes is not enough on its own: Microsoft's viewer matches links with a regular expression that ignores escapes, so a `(` after `]` is escaped too. HTML and SARIF placeholders are neutralised as well, and a property test checks that arbitrary input never yields a link while losing nothing.
- **URI scheme injection and invalid URIs.** A file named `javascript:alert(1)` at the root of a scan would otherwise become a URI with a scheme, and GitHub rejects the whole upload for one invalid URI. Paths are percent-encoded from their exact bytes, with `:` always encoded.
- **Wrong locations.** Offsets into the decompressed dataset of a deflated file were indistinguishable from file offsets (in JSON too). Findings now record which bytes their offset counts, and only file offsets become SARIF regions.
- **Privacy.** The SARIF log does not record the absolute path of the scanning machine, the command line, the environment or the machine name.

## Residual risks

- RG-04 above 64 MiB on POSIX.
- File symlinks are followed: the scanner reads whatever the invoking user can read. There is no privilege boundary to cross, but scanning as root is not recommended.
- Signature search runs at about 50 to 80 MB/s per core, bounded by the 1 GiB window. Parallel scanning is on the roadmap.
- File names are part of every report by necessity. DICOM file and directory names can contain patient identifiers, so a report of such an archive should only go to systems approved for patient data.
