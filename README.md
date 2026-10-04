# RadGuard

**An integrity and safety scanner for medical imaging.** RadGuard looks inside DICOM files (CT, MRI, X-ray) for three things hospitals currently have no unified way to check:

1. **Hidden malware.** A scan that is also an executable.
2. **Patient data leaks.** Names, IDs and dates left in metadata or burned into pixels.
3. **Tampered images.** Tumours injected into or erased from a scan.

> Status: early development (v0.1.0.dev0). The structural scanner works today; the other layers are on the [roadmap](ROADMAP.md).

---

## Why this exists

Billions of DICOM images move between scanners, PACS archives, cloud storage, AI models and research datasets. Almost none of them are verified at any point.

| Threat | What is known | What defenders have today |
|---|---|---|
| **Polyglot malware** | A DICOM file's 128-byte preamble can hold a Windows PE header, making one file both a valid CT slice and a runnable program ([CVE-2019-11687](https://nvd.nist.gov/vuln/detail/CVE-2019-11687)). The same trick works with Linux ELF binaries against Linux-based imaging devices ([ELFDICOM](https://www.praetorian.com/blog/elfdicom-poc-malware-polyglot-exploiting-linux-based-medical-devices/)). The standard still permits it. | Generic polyglot tools that don't understand DICOM. Advice to "inspect the preamble." |
| **PHI leakage** | Patient identifiers survive in private tags, free-text fields and text burned into pixel data, including in "de-identified" research releases. | Network-traffic tools ([DicomGhost](https://github.com/shaan3000/dicomghost)) and redaction libraries, but no file-level audit across tags *and* pixels. |
| **Image tampering** | [CT-GAN](https://www.usenix.org/conference/usenixsecurity19/presentation/mirsky) (USENIX Security 2019) injected and removed lung nodules in CT scans, and radiologists and an AI screening model were fooled. | Research papers and datasets ([LuNoTim-CT](https://par.nsf.gov/servlets/purl/10279866), [cascade detectors](https://arxiv.org/abs/2205.15170)). No deployable tool. |

RadGuard combines these defences into a single scanner that can run on a laptop, inline between a modality and the PACS, or across an entire cloud archive.

## Architecture

```
            +-------------------- radguard scan / radguard proxy --------------------+
 DICOM  --> | L1 structure  | L2 privacy        | L3 integrity        | L4 provenance  | --> findings
 files      | preamble,     | PHI in tags,      | HU/noise forensics, | signatures,    |     (text/JSON/
            | trailing data,| burned-in pixel   | metadata-vs-pixel   | chain of       |      SARIF)
            | embedded docs | text (GPU OCR)    | consistency, 3D CNN | custody        |
            +--------------------------------------------------------------------------+
```

- [x] **L1 structure:** polyglot preamble detection (PE, ELF, Mach-O, scripts, ZIP, OLE, PDF, HTML/SVG)
- [ ] L1: trailing data, encapsulated documents, oversized private blobs
- [ ] **L2 privacy:** tag-level PHI rules (PS3.15 Annex E) and burned-in text detection
- [ ] **L3 integrity:** tamper and deepfake detection for CT, GPU-accelerated
- [ ] **L4 provenance:** DICOM digital signatures and verification
- [ ] DICOM firewall mode (C-STORE proxy that quarantines files in flight)
- [ ] Cloud scale: S3 / AWS HealthImaging batch scanning

## Quickstart

```bash
git clone https://github.com/<you>/radguard && cd radguard
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
radguard scan /path/to/dicom/
```

```
CRITICAL  preamble.pe-polyglot       demo/series1/IM0002
          Windows PE executable embedded via preamble (PE/DICOM polyglot)
          MZ header with PE signature at offset 0xb4; the file is laid out as a Windows executable as well as a DICOM image
CRITICAL  preamble.elf-polyglot      demo/series1/IM0003
          ELF executable header in preamble (ELF/DICOM polyglot)
          first bytes 7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00; entropy 0.44 bits/byte; 2% printable
MEDIUM    preamble.pdf               demo/report.dcm
          PDF header in preamble
          first bytes 25 50 44 46 2d 31 2e 37 00 00 00 00 00 00 00 00; entropy 0.52 bits/byte; 6% printable

scanned 5 files: 4 DICOM, 1 skipped, 0 errors; findings: critical=2, medium=1
```

Options: `--format json` for machine-readable output, and `--fail-on {info,low,medium,high,critical}` to set the severity that makes the command exit with status 1 (useful in pipelines).

## Responsible use

- Only scan data you are authorised to access. RadGuard never connects to remote systems you don't point it at.
- Test fixtures are synthetic and benign: correct headers, no working payloads.
- Issues found in public datasets are reported privately to their maintainers before anything is published.

## License

MIT
