# Roadmap (12 weeks, Oct 2026 to Dec 2026)

Every day gets one real, commit-sized task. If a day runs short, the minimum is a test, a fixture, or a [devlog](docs/devlog.md) entry about what you learned. Never an empty commit.

## Phase 1: Structural scanner (weeks 1-2)

### Week 1
- [x] D1: Scaffold, preamble polyglot detection (PE/ELF/Mach-O/script/ZIP/OLE/PDF/markup), tests, CI
- [x] D2: Byte-coverage DICOM parser written from scratch (all native encodings, sequences, encapsulated, deflate); hidden-payload, pixel-contract and 31 structural checks; `radguard map`; fuzzing; differential tests vs pydicom
- [x] D3: Self-audit (9 findings fixed, regression-tested); budgeted carving engine; value-level carving with element paths; encapsulated documents; JPEG/JPEG-LS/J2K/RLE codestream analysis
- [x] D4: Engineering review (fail-closed exit status and directory errors, bare datasets, strict typing, mutation testing) and private-data analysis with budgeted decompression of compressed private values
- [x] D5: SARIF 2.1.0 output, verified by a real upload to GitHub code scanning in CI; rule catalog (80 rules, CWE mapping, generated reference); offsets labelled file vs decompressed; output hardening (RG-14 to RG-17)
- [ ] D6: Multiprocessing; benchmark files/sec on 10k files
- [ ] D7: Blog post #1, "Your CT scan can be an .exe"

### Week 2
- [ ] Assemble a test corpus: pydicom test files plus public TCIA collections (licence-compliant)
- [ ] Malformed-file robustness: truncated elements, bad lengths, undefined-length sequences (fuzz with Hypothesis)
- [ ] DICOMDIR and ZIP-of-studies input support
- [ ] First corpus run; record baseline stats in `docs/results.md`

## Phase 2: Privacy / PHI (weeks 3-4)
- [ ] Tag rules from PS3.15 Annex E (Basic Application Level Confidentiality Profile)
- [ ] Free-text tag scanning (names, MRNs, dates, phone numbers) with confidence scores
- [ ] Burned-in pixel text: GPU OCR (CUDA) on windowed pixel data, with region boxes in the report
- [ ] Per-study PHI risk score
- [ ] Scan public "de-identified" datasets, then disclose privately to maintainers

## Phase 3: Integrity / tamper detection (weeks 5-8)
- [ ] Build the attack: CT-GAN-style nodule injection and removal on LIDC-IDRI (MONAI, 3D inpainting)
- [ ] Forensic baselines: HU distribution and noise-residual inconsistency, slice-to-slice continuity
- [ ] Metadata-vs-pixel consistency (kVp, mAs, kernel, slice thickness vs observed noise)
- [ ] 3D CNN detector trained on generated tampered data; compare against published baselines
- [ ] Optimise inference on GPU (batching, mixed precision, TensorRT); report scans/sec

## Phase 4: Deployment (weeks 9-11)
- [ ] `radguard proxy`: DICOM C-STORE firewall (pynetdicom) that quarantines flagged files in flight
- [ ] Provenance: DICOM digital signatures (PS3.15 Annex C): sign on ingest, verify on read
- [ ] Cloud: S3 event, then a container scan, then findings; AWS HealthImaging connector
- [ ] Throughput and cost per million images, measured, not estimated

## Phase 5: Ship (week 12)
- [ ] v1.0 on PyPI and a Docker image
- [ ] Technical write-up (arXiv) and a conference talk submission
- [ ] 3-minute demo video
