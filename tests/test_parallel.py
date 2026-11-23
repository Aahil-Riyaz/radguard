"""Parallel scanning: identical results to a serial scan, deterministic order, fail-closed on crashes.

The workers are real processes (spawned, as on Windows), so the checks passed to them here are
module-level functions that can be pickled by reference.
"""

import json
import os

import pytest

from builder import el
from conftest import build_dicom, build_pe_polyglot
from radguard import scanner
from radguard.checks import ALL_CHECKS
from radguard.cli import main
from radguard.scanner import resolve_jobs, scan_paths

MARKER = b"RADGUARD-CRASH-MARKER"


def crash_on_marker(ctx):
    """A check standing in for a parser that dies in native code on one hostile file."""
    if MARKER in bytes(ctx.buf):
        os._exit(1)  # no exception, no cleanup: exactly what a segfault or the OOM killer looks like
    return []


def _tree(root, count=12):
    """A tree with clean files, polyglots, non-DICOM files and a nested directory."""
    (root / "sub" / "deeper").mkdir(parents=True)
    for i in range(count):
        folder = (root, root / "sub", root / "sub" / "deeper")[i % 3]
        if i % 4 == 0:
            data = build_pe_polyglot()
        elif i % 4 == 1:
            data = b"plain text, not dicom " * 20
        else:
            data = build_dicom()
        (folder / f"f{i:02d}.dcm").write_bytes(data)
    return root


def test_parallel_results_equal_serial_results_in_the_same_order(tmp_path):
    root = _tree(tmp_path)
    serial = list(scan_paths([str(root)], jobs=1))
    assert any(r.findings for r in serial) and any(not r.is_dicom for r in serial)
    for jobs, batch in ((2, 1), (2, 5), (3, 2), (4, 1000)):
        assert list(scan_paths([str(root)], jobs=jobs, batch_size=batch)) == serial


def test_order_is_kept_when_the_walk_reports_something_between_batches(tmp_path):
    root = _tree(tmp_path, count=9)
    try:
        os.symlink(root / "sub", root / "a-link", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("cannot create symbolic links here")
    serial = list(scan_paths([str(root)], jobs=1))
    assert any(r.note for r in serial)
    assert list(scan_paths([str(root)], jobs=3, batch_size=2)) == serial


def test_missing_and_unreadable_paths_are_reported_not_dropped(tmp_path):
    root = _tree(tmp_path, count=3)
    paths = [str(root), str(tmp_path / "missing.dcm")]
    serial = list(scan_paths(paths, jobs=1))
    parallel = list(scan_paths(paths, jobs=2, batch_size=2))
    assert parallel == serial
    assert serial[-1].error  # the missing file is an error, so the scan is incomplete


def test_cli_report_is_identical_for_any_number_of_jobs(tmp_path, capsys):
    _tree(tmp_path)
    reports = []
    for jobs in ("1", "2", "4"):
        status = main(["scan", str(tmp_path), "--format", "json", "--jobs", jobs])
        reports.append((status, json.loads(capsys.readouterr().out)))
    assert reports[0] == reports[1] == reports[2]
    assert reports[0][0] == 1  # the polyglots still fail the build


def test_a_worker_that_dies_is_isolated_and_the_scan_is_incomplete_not_clean(tmp_path):
    (tmp_path / "a.dcm").write_bytes(build_dicom())
    (tmp_path / "b.dcm").write_bytes(build_dicom(body=el(0x00091010, "OB", MARKER)))
    (tmp_path / "c.dcm").write_bytes(build_dicom())
    # One batch holds all three files, so the crash takes down the whole batch's worker
    results = list(scan_paths([str(tmp_path)], checks=(crash_on_marker,), jobs=2, batch_size=3))

    by_name = {os.path.basename(r.path): r for r in results}
    assert list(by_name) == ["a.dcm", "b.dcm", "c.dcm"]  # nothing lost, order kept
    assert by_name["a.dcm"].error is None and by_name["a.dcm"].is_dicom
    assert by_name["c.dcm"].error is None and by_name["c.dcm"].is_dicom
    assert "died" in by_name["b.dcm"].error  # the culprit, and only the culprit, is named


def test_the_pool_replaces_itself_so_later_batches_still_get_scanned(tmp_path):
    (tmp_path / "a.dcm").write_bytes(build_dicom(body=el(0x00091010, "OB", MARKER)))
    for i in range(6):
        (tmp_path / f"b{i}.dcm").write_bytes(build_dicom())
    results = list(scan_paths([str(tmp_path)], checks=(crash_on_marker,), jobs=2, batch_size=1))
    assert [r.error is not None for r in results] == [True] + [False] * 6


def test_a_check_that_cannot_be_sent_to_a_worker_is_an_error_not_a_crash(tmp_path):
    (tmp_path / "a.dcm").write_bytes(build_dicom())
    (tmp_path / "b.dcm").write_bytes(build_dicom())
    results = list(scan_paths([str(tmp_path)], checks=(lambda ctx: [],), jobs=2, batch_size=1))
    assert len(results) == 2
    assert all(r.error and "worker failed" in r.error for r in results)


def test_default_checks_are_what_workers_run(tmp_path):
    (tmp_path / "evil.dcm").write_bytes(build_pe_polyglot())
    (result,) = scan_paths([str(tmp_path)], checks=ALL_CHECKS, jobs=2)
    assert "preamble.pe-polyglot" in {f.check for f in result.findings}


@pytest.mark.parametrize("bad", [-1, -8])
def test_negative_jobs_are_rejected(bad):
    with pytest.raises(ValueError, match="jobs"):
        resolve_jobs(bad)


def test_zero_jobs_means_one_per_cpu_and_is_capped(monkeypatch):
    monkeypatch.setattr(scanner.os, "cpu_count", lambda: 8)
    assert resolve_jobs(0) == 8
    monkeypatch.setattr(scanner.os, "cpu_count", lambda: None)
    assert resolve_jobs(0) == 1
    assert resolve_jobs(10_000) == scanner.MAX_JOBS
    assert resolve_jobs(1) == 1


def test_serial_scan_does_not_start_any_processes(tmp_path, monkeypatch):
    (tmp_path / "a.dcm").write_bytes(build_dicom())

    def boom(*args, **kwargs):
        raise AssertionError("a serial scan must not create a process pool")

    monkeypatch.setattr(scanner, "ProcessPoolExecutor", boom)
    assert len(list(scan_paths([str(tmp_path)], jobs=1))) == 1
