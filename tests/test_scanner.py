"""Scanner and CLI: what gets scanned, what fails closed, and what the exit status means."""

import json
import os
import random

import pytest

from builder import el, fake_pe, image, meta, part10
from radguard import scanner
from radguard.cli import EXIT_CLEAN, EXIT_FINDINGS, EXIT_INCOMPLETE, main
from radguard.dicom import coverage, looks_like_dataset, parse

# -- bare datasets (no preamble, no DICM): lenient readers accept them, so must we --------------

def test_bare_dataset_is_analysed_not_skipped(write_file):
    result = scanner.scan_file(write_file("bare", image(8, 8) + fake_pe()))
    assert result.is_dicom
    assert {"structure.no-part10-header", "structure.hidden-payload"} <= {f.check for f in result.findings}


@pytest.mark.parametrize("dataset", [image(4, 4), image(4, 4, implicit=True), meta() + image(4, 4)],
                         ids=["explicit", "implicit", "with-file-meta"])
def test_bare_datasets_are_recognised_and_fully_explained(dataset):
    assert looks_like_dataset(dataset)
    parsed = parse(dataset, part10=False)
    assert [a.code for a in parsed.anomalies] == ["no-part10-header"]
    assert coverage.gaps(parsed.regions, len(dataset)) == []


@pytest.mark.parametrize("data", [
    b"", b"hello world " * 100, bytes(range(256)) * 16, b"PK\x03\x04" + bytes(100), b"%PDF-1.7\n" + bytes(100),
    b"\x08\x00\x16\x00" + bytes(60),  # right first group, then nonsense
], ids=["empty", "text", "bytes", "zip", "pdf", "near-miss"])
def test_ordinary_files_are_not_mistaken_for_datasets(data):
    assert not looks_like_dataset(data)


def test_random_data_starting_with_a_dataset_group_is_still_rejected():
    rng = random.Random(7)
    for _ in range(2000):  # worst case: the first two bytes already look like group 0008
        assert not looks_like_dataset(b"\x08\x00" + rng.randbytes(510))


def test_non_dicom_files_are_rejected_after_reading_only_their_head(write_file, monkeypatch):
    reads = []
    real_read = scanner._read
    monkeypatch.setattr(scanner, "_read", lambda fd, n: reads.append(n) or real_read(fd, n))
    assert not scanner.scan_file(write_file("video.mp4", bytes(5 << 20))).is_dicom
    assert reads == [scanner.SNIFF_LEN]


# -- failing closed --------------------------------------------------------------------------

def test_unreadable_directory_is_reported_not_skipped(tmp_path, monkeypatch):
    locked = tmp_path / "locked"
    locked.mkdir()
    (tmp_path / "a.dcm").write_bytes(part10(image(4, 4)))
    real_scandir = os.scandir

    def scandir(path="."):
        if os.fspath(path) == str(locked):
            raise PermissionError(13, "Permission denied", str(locked))
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", scandir)
    results = list(scanner.scan_paths([str(tmp_path)]))
    [error] = [r for r in results if r.error]
    assert error.path == str(locked) and "cannot list directory" in error.error
    assert [r.is_dicom for r in results if not r.error] == [True]


def test_symlinked_directory_is_noted_not_silently_skipped(tmp_path):
    target, root = tmp_path / "real", tmp_path / "scan"
    target.mkdir()
    root.mkdir()
    try:
        os.symlink(target, root / "link", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("creating symlinks is not permitted here")
    assert [r.note for r in scanner.scan_paths([str(root)])] == ["symbolic link to a directory: not followed"]


# -- exit status --------------------------------------------------------------------------------

def test_exit_status_clean_and_findings(write_file):
    assert main(["scan", write_file("clean.dcm", part10(image(4, 4)))]) == EXIT_CLEAN
    assert main(["scan", write_file("evil.dcm", part10(image(4, 4)) + fake_pe())]) == EXIT_FINDINGS


def test_incomplete_scan_takes_precedence_over_findings(write_file, tmp_path, capsys):
    evil = write_file("evil.dcm", part10(image(4, 4)) + fake_pe())
    status = main(["scan", evil, str(tmp_path / "missing.dcm"), "--format", "json"])
    report = json.loads(capsys.readouterr().out)
    assert status == EXIT_INCOMPLETE
    assert report["summary"]["complete"] is False
    assert report["summary"]["findings"]["critical"] == 1  # findings are still reported


def test_json_report_identifies_tool_and_schema(write_file, capsys):
    main(["scan", write_file("a.dcm", part10(el(0x00100010, "PN", "X"))), "--format", "json"])
    report = json.loads(capsys.readouterr().out)
    assert report["tool"]["name"] == "radguard" and report["schema_version"] == 1
    assert report["summary"]["complete"] is True
