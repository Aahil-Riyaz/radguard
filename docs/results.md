# Results

## Scan throughput

`radguard scan --jobs N` scans with N worker processes. The report is byte-for-byte the same for any N
(same findings, same order); only the wall-clock time changes. Reproduce with
[`scripts/benchmark.py`](../scripts/benchmark.py).

**Corpus:** 10,000 synthetic files in 100 folders, 634 MB: 70% clean images (4 KB to 256 KB of pixels),
20% polyglots with a hidden PE signature, 10% non-DICOM files. 4,883 findings.
**Machine:** Windows 11, 16 logical CPUs, Python 3.14, local disk. Best of 3 runs, after an untimed warm-up pass.

| Workers | Seconds | Files/s | Speedup |
|---:|---:|---:|---:|
| 1 (serial) | 14.21 | 704 | 1.00x |
| 2 | 8.03 | 1,246 | 1.77x |
| 4 | 4.41 | 2,266 | 3.22x |
| 8 | 2.94 | 3,406 | 4.84x |
| 16 | 3.07 | 3,261 | 4.63x |

Every setting produced identical results; the benchmark exits with an error if they ever differ.

**Reading the numbers**

- Scaling is sub-linear and stops at 8 workers. The directory walk stays serial, results are returned
  in order through one process, and past a few workers the disk and the parent process are the limit, not the CPU.
- Files are sent to workers in batches of 32. One task per file spent more time on inter-process
  messaging than on scanning small files (`DEFAULT_BATCH` in `scanner.py`).
- **A first benchmark overstated the speedup, and this is why the benchmark now warms up.** The first read
  of freshly written files was about 7x slower than later reads (OS file cache and, on Windows, real-time
  antivirus). That cost landed on the serial baseline, which made 2 workers look 6.4x faster, which cannot be
  true for CPU-bound work. Timing repeated serial passes showed the cause (105 files/s cold, about 700 warm), and an untimed
  warm-up pass now precedes every measurement. A speedup above the worker count is a sign the baseline is wrong.
- These are warm-cache numbers. A cold archive on a network share will be limited by I/O, and the gain from
  more workers will be smaller.

## Fail-closed under crashes

A worker that dies (killed, out of memory, or a crash in native code) cannot say which file did it. The
scanner re-runs the files of that batch one at a time in fresh processes, so the culprit is named exactly and
reported as an error; the scan then exits with status 3 (incomplete) instead of looking clean. The pool replaces
itself, so later files are still scanned. Covered by `tests/test_parallel.py`.
