# Security policy

RadGuard reads hostile files by design, so bugs in RadGuard itself are security bugs.

## Reporting

Please report vulnerabilities privately via GitHub's **Report a vulnerability** button (Security tab), not as a public issue. Include a minimal reproducing file if you can. Synthetic files are preferred: never send real patient data.

## What counts

- Any input (file contents, file names, directory layout) that makes RadGuard crash, hang, or use unbounded memory or time
- Any way to hide content from RadGuard *without* RadGuard reporting that its analysis was incomplete
- Any way for scanned content to affect the analyst's terminal or the machine running RadGuard

## Hardening record

The threat model, findings and fixes are documented in [docs/security/self-audit.md](docs/security/self-audit.md), and every fix is pinned by a regression test in `tests/test_hostile.py`.
