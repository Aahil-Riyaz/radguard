# RadGuard

**An integrity and safety scanner for medical imaging.** RadGuard opens DICOM files (CT, MRI, X-ray) and checks three things hospitals currently have no unified way to check:

1. **Hidden malware.** A scan that is also an executable, or carries one.
2. **Patient data leaks.** Names, IDs and dates left in metadata or burned into pixels.
3. **Tampered images.** Findings injected into or erased from a scan, or a file that shows different images to different software.

> Status: early development. Structural analysis works today; privacy and AI tamper detection are on the [roadmap](ROADMAP.md).

<p align="center">
  <img src="docs/img/two-scans-one-file.png" alt="Two different CT slices extracted from the same DICOM file" width="640">
</p>

**One file, two scans.** Both images above were extracted from the *same* 33 KB DICOM file ([`examples/two-scans-one-file.dcm`](examples/two-scans-one-file.dcm)). Left: the first Pixel Data element, read by RadGuard's parser. Right: what pydicom returns, since it silently keeps the last copy. A radiologist's viewer and an AI pipeline can be shown different scans. RadGuard flags it:

```
CRITICAL  pixels.duplicate-pixel-data        examples/two-scans-one-file.dcm
          Two images in one file
          2 Pixel Data elements at 0x182, 0x418e. Software that keeps the first copy and software
          that keeps the last display different images from the same file, ...
```

---

## Why this exists

| Threat | What is known | What defenders have today |
|---|---|---|
| **Polyglot malware** | A DICOM preamble can hold a Windows PE header, making one file both a valid CT slice and a program ([CVE-2019-11687](https://nvd.nist.gov/vuln/detail/CVE-2019-11687)). The same works with Linux ELF against Linux-based devices ([ELFDICOM](https://www.praetorian.com/blog/elfdicom-poc-malware-polyglot-exploiting-linux-based-medical-devices/)). | Generic polyglot tools that don't understand DICOM. |
| **PHI leakage** | Identifiers survive in private tags, free text and burned-in pixels, even in "de-identified" releases. | Network-level tools ([DicomGhost](https://github.com/shaan3000/dicomghost)) and redaction libraries; no file-level audit across tags *and* pixels. |
| **Image tampering** | [CT-GAN](https://www.usenix.org/conference/usenixsecurity19/presentation/mirsky) (USENIX Security 2019) injected and removed lung nodules in CT scans and fooled radiologists and an AI model. | Research papers and datasets. No deployable tool. |

## How it works: account for every byte

A conforming DICOM file can be explained completely: a preamble, a magic number, then a tree of element headers and values. RadGuard's parser is written from scratch to do exactly that and to report **every byte the structure cannot explain**, because that is where payloads hide. Off-the-shelf DICOM libraries can't do this: they are built to read files, so they guess past malformed structure. See the [parser design](docs/design/parser.md).

```
$ radguard map examples/appended-executable.dcm
17,294 bytes, Explicit VR Little Endian

  offset      length  structure
00000000         128  Preamble (all zero)
00000080           4  'DICM' magic
00000084           4  (0002,0000) UL  FileMetaInformationGroupLength 108
  ...
00000146           2  (0028,0010) US  Rows                         128
00000150           2  (0028,0011) US  Columns                      128
00000182      16,384  (7FE0,0010) OB  PixelData                    <16,384 bytes of pixels>
0000418E              !! invalid-vr: (5A4D,0000) has VR bytes 00 00, which is not a VR
0000418E         512  ?? UNEXPLAINED  contains Windows PE executable at 0x418e; ...

coverage: 97.04% of bytes explained by the DICOM structure  [preamble 128 | magic 4 | header 136 | value 16,514 | unexplained 512]
```

Patient-identifying values are masked in the map unless you pass `--show-phi`.

### Parser differentials, verified

The most dangerous files aren't malformed, just *ambiguous*: different software reads them differently. Every row below is an executable test against pydicom 3.0.2 ([`tests/test_differential.py`](tests/test_differential.py)):

| Crafted file | What pydicom does | RadGuard finding |
|---|---|---|
| Two Pixel Data elements | Shows the last one, silently | `pixels.duplicate-pixel-data` (critical) |
| Pixel Data longer than the image | Returns the extra bytes as **extra frames** | `pixels.slack` ("1 hidden frame(s)") |
| Executable appended after the dataset | Parses it as invented attributes (`MZ` becomes group `0x5A4D`) | `structure.hidden-payload` (critical) |
| Wrong transfer syntax in the header | Switches encoding with a warning | `structure.transfer-syntax-mismatch` |
| Duplicate Patient Name | Keeps the last | `structure.duplicate-tag` |

## What it detects today

- **Preamble polyglots:** PE (with `e_lfanew` followed to a real PE header), ELF, Mach-O, scripts, ZIP/JAR, OLE/MSI, PDF, HTML/SVG
- **Hidden payloads:** executables and archives in bytes outside the DICOM structure, after a deflate stream, or in trailing padding
- **Files inside attribute values:** every value is searched, and findings name the exact location, e.g. `(0008,1140) item 2 > (0029,1010) Private`
- **Encapsulated documents:** declared MIME type checked against the real content; executables inside documents
- **Compressed frames:** codestream walkers for JPEG, JPEG-LS and JPEG 2000 follow the marker structure to each frame's true end (not the first `FF D9`: EXIF thumbnails and J2K comments contain those too), then flag data after the end, a second hidden image, frames that aren't the declared codec, malformed codestreams and undeclared frames
- **Pixel contract violations:** duplicate images, hidden frames and slack, executables stored as pixels, truncated pixel data, 32-bit size overflow (heap-overflow trigger), encoding contradicting the transfer syntax
- **30+ structural anomalies**, each with the reason it matters: lying lengths, transfer-syntax mismatch, VR confusion, unterminated sequences, decompression bombs, recursion bombs, corrupt fragment tables, ...

## Engineering

- **Parser written from scratch** for every native encoding (implicit/explicit, little/big endian, deflated), nested and undefined-length sequences, encapsulated pixel data and Basic Offset Tables. Zero runtime dependencies; files are memory-mapped, never copied.
- **Never crashes on hostile input.** Errors become anomalies; parsing resumes at the nearest boundary whose length can still be trusted.
- **Fuzzed:** Hypothesis property tests check that the parser, the codec walkers and every check terminate and that byte accounting is exact for any input (150,000 cases in deep mode: `HYPOTHESIS_PROFILE=deep pytest tests/test_fuzz.py`). The harness is mutation-tested: a planted length-trusting bug is caught in about a second.
- **Every claim about other software is a test**, so documentation can't drift from reality.

## Security of RadGuard itself

A scanner that reads hostile files is itself a target. RadGuard has been [self-audited](docs/security/self-audit.md) against an attacker who controls file bytes, file names, the directory layout and timing: 9 findings, all fixed, each pinned by a regression test named after its ID ([`tests/test_hostile.py`](tests/test_hostile.py)).

- **Budgets fail loud.** Every limit (search window, candidate budget, depth, element count, inflated size) is reported when reached. Flooding a file with decoy signatures to bury a real one produces a high finding instead of a blind spot.
- **Hostile file systems:** FIFOs and device files are never opened for reading (race-free `fstat` on the descriptor); small files are read privately so a file truncated mid-scan can't crash the process.
- **Safe output:** terminal escape sequences and Unicode bidi overrides in file names or contents are escaped before printing.
- **Bounded work:** every loop over attacker data runs in C or advances by at least one structure, with caps; pathological inputs are timed in tests.

Report vulnerabilities privately: see [SECURITY.md](SECURITY.md).

## Quickstart

```bash
git clone https://github.com/Aahil-Riyaz/radguard && cd radguard
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
radguard scan examples/
radguard map examples/two-scans-one-file.dcm
```

`radguard scan` takes files or directories, `--format json` for machine-readable output, and `--fail-on {info,low,medium,high,critical}` to choose the severity that makes it exit with status 1 (for CI and ingest pipelines).

## Roadmap

- [x] **L1 structure:** preamble polyglots, byte-coverage parser, hidden payloads, pixel contract, parser differentials
- [x] L1: value-level carving, encapsulated documents, codestream analysis, self-audit
- [ ] L1: private-tag analysis; SARIF output; parallel scanning
- [ ] **L2 privacy:** PHI in tags (PS3.15 Annex E) and burned-in pixel text (GPU OCR)
- [ ] **L3 integrity:** CT tamper and deepfake detection, GPU-accelerated
- [ ] **L4 provenance:** DICOM digital signatures
- [ ] DICOM firewall mode (C-STORE proxy that quarantines files in flight)
- [ ] Cloud scale: S3 / AWS HealthImaging batch scanning

## Responsible use

- Only scan data you are authorised to access. RadGuard never connects to systems you don't point it at.
- Examples and test fixtures are synthetic and inert: correct headers, no working code.
- Issues found in public datasets are reported privately to their maintainers before anything is published.

## License

MIT
