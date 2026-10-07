"""Generate the example files in examples/ and the README figure.

Every example is synthetic and inert (executable *headers* only, no code).
The figure is produced from the generated file itself: copy 1 is extracted
with RadGuard's parser, copy 2 with pydicom, so the image is evidence, not an
illustration.

    python scripts/make_examples.py
"""

from __future__ import annotations

import io
import struct
import sys
import warnings
import zlib
from pathlib import Path

import numpy as np
import pydicom

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

from builder import PIXEL_DATA, el, fake_pe, image, part10  # noqa: E402
from radguard.dicom import parse  # noqa: E402

N = 128


def phantom(lesion: bool) -> np.ndarray:
    """An axial chest-CT-like slice: body, lungs, heart, spine, optional lung nodule."""
    y, x = np.mgrid[0:N, 0:N]

    def ellipse(cx, cy, rx, ry):
        return ((x - cx) / rx) ** 2 + ((y - cy) / ry) ** 2 <= 1

    img = np.zeros((N, N))
    img[ellipse(64, 66, 58, 44)] = 115   # soft tissue
    img[ellipse(40, 60, 17, 27)] = 18    # right lung
    img[ellipse(88, 60, 17, 27)] = 18    # left lung
    img[ellipse(68, 72, 13, 11)] = 135   # heart
    img[ellipse(64, 100, 8, 7)] = 235    # vertebra
    if lesion:
        r = np.hypot(x - 92, y - 50)
        img = np.maximum(img, np.where(r <= 5.5, 160 - 6 * r, 0))  # ~1 cm solid nodule
    img += np.random.default_rng(7).normal(0, 4, img.shape)  # scanner noise
    return np.clip(img, 0, 255).astype(np.uint8)


def write_png(path: Path, pixels: np.ndarray) -> None:
    h, w = pixels.shape
    raw = b"".join(b"\x00" + pixels[row].tobytes() for row in range(h))

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    path.write_bytes(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 0, 0, 0, 0))
                     + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def main(out: Path = ROOT / "examples", fig: Path = ROOT / "docs" / "img" / "two-scans-one-file.png") -> None:
    out.mkdir(parents=True, exist_ok=True)
    clean, tampered = phantom(False).tobytes(), phantom(True).tobytes()

    two_scans = part10(image(N, N, clean) + el(PIXEL_DATA, "OB", tampered))
    samples = {
        "clean.dcm": part10(image(N, N, clean)),
        "two-scans-one-file.dcm": two_scans,
        "hidden-frame.dcm": part10(image(N, N, clean + tampered)),
        "appended-executable.dcm": part10(image(N, N, clean)) + fake_pe(512),
        "preamble-polyglot.dcm": _preamble_polyglot(clean),
    }
    for name, data in samples.items():
        (out / name).write_bytes(data)

    # The figure: both copies, extracted from the same bytes by two parsers.
    first = next(e for e in parse(two_scans).elements if e.tag == PIXEL_DATA)
    copy1 = np.frombuffer(two_scans[first.value_offset : first.end], np.uint8).reshape(N, N)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        copy2 = pydicom.dcmread(io.BytesIO(two_scans)).pixel_array
    scale, gap = 3, np.full((N * 3, 12), 255, np.uint8)
    big = [np.kron(c, np.ones((scale, scale), np.uint8)) for c in (copy1, copy2)]
    fig.parent.mkdir(parents=True, exist_ok=True)
    write_png(fig, np.hstack([big[0], gap, big[1]]))
    print(f"wrote {len(samples)} examples to {out} and {fig}")


def _preamble_polyglot(pixels: bytes) -> bytes:
    # MZ stub in the preamble; its e_lfanew points at a PE signature inside a private element.
    marker = b"PE\x00\x00"
    private = el(0x00291010, "OB", bytes(8) + marker + bytes(4))  # sorts between (0028,xxxx) and Pixel Data
    data = bytearray(part10(image(N, N, pixels, extra=private)))
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, data.index(marker))
    return bytes(data)


if __name__ == "__main__":
    main()
