"""Measure scan throughput (files/second) for different numbers of worker processes.

Builds a synthetic corpus in a temporary directory (nothing is written elsewhere), scans it
serially and with each requested worker count, checks that every run produced exactly the
same results, and prints a table.

    python scripts/benchmark.py                  # 10,000 files, 1/2/4/8 workers
    python scripts/benchmark.py -n 2000 -j 1 4   # a quicker run

The corpus is a mix meant to resemble a real archive: mostly clean images of varied size,
some polyglot files, and some non-DICOM files that the scanner must reject cheaply.
"""

from __future__ import annotations

import argparse
import os
import platform
import random
import struct
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

from builder import el, image, part10  # noqa: E402
from radguard.scanner import resolve_jobs, scan_paths  # noqa: E402


def polyglot(rng: random.Random) -> bytes:
    """MZ header in the preamble whose e_lfanew points at a hidden PE signature (inert: headers only)."""
    body = el(0x00091010, "OB", bytes(rng.randrange(8, 64)) + b"PE\x00\x00" + bytes(4))
    data = bytearray(part10(body, preamble=b"MZ"))
    struct.pack_into("<I", data, 0x3C, data.index(b"PE\x00\x00"))
    return bytes(data)


def build_corpus(root: Path, count: int, seed: int = 1) -> int:
    """Write `count` files into a tree of 100-file folders; return the total size in bytes."""
    rng = random.Random(seed)
    total = 0
    for i in range(count):
        folder = root / f"study{i // 100:04d}"
        folder.mkdir(exist_ok=True)
        kind = rng.random()
        if kind < 0.70:  # clean image, 4 KB to 256 KB of pixels
            side = rng.choice((64, 128, 256, 512))
            data = part10(image(side, side, bytes(rng.randrange(256) for _ in range(64)) * (side * side // 64)))
        elif kind < 0.90:
            data = polyglot(rng)
        else:  # not DICOM at all
            data = rng.randbytes(rng.randrange(512, 20_000))
        (folder / f"img{i:06d}.dcm").write_bytes(data)
        total += len(data)
    return total


def run(root: Path, jobs: int) -> tuple[float, list]:
    start = time.perf_counter()
    results = list(scan_paths([str(root)], jobs=jobs))
    return time.perf_counter() - start, results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-n", "--files", type=int, default=10_000)
    parser.add_argument("-j", "--jobs", type=int, nargs="+", default=[1, 2, 4, 8])
    parser.add_argument("--repeat", type=int, default=3, help="runs per setting; the best is reported")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="radguard-bench-") as tmp:
        root = Path(tmp)
        print(f"building {args.files:,} files ...", flush=True)
        size = build_corpus(root, args.files)
        print(f"corpus: {args.files:,} files, {size / 1e6:,.0f} MB; python {platform.python_version()}, "
              f"{platform.system()}, {os.cpu_count()} CPUs\n")

        # Untimed warm-up. The first read of freshly written files is several times slower than
        # later reads (OS file cache, and on Windows real-time antivirus); without this the first
        # setting measured, the serial baseline, would be charged for it and every speedup inflated.
        print("warming the file cache ...", flush=True)
        baseline_results = list(scan_paths([str(root)], jobs=1))
        baseline_rate = None
        print(f"{'workers':>8} {'seconds':>9} {'files/s':>9} {'speedup':>8}")
        for jobs in args.jobs:
            best = float("inf")
            for _ in range(args.repeat):
                elapsed, results = run(root, jobs)
                best = min(best, elapsed)
                if baseline_results is None:
                    baseline_results = results
                elif results != baseline_results:
                    print(f"FAIL: results with {jobs} workers differ from the first run", file=sys.stderr)
                    return 1
            rate = args.files / best
            baseline_rate = baseline_rate or rate
            print(f"{resolve_jobs(jobs):>8} {best:>9.2f} {rate:>9,.0f} {rate / baseline_rate:>7.2f}x")
        findings = sum(len(r.findings) for r in baseline_results)
        print(f"\nevery run produced identical results ({findings:,} findings across the corpus)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
