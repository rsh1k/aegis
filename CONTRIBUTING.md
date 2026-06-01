# Contributing to Aegis

Thanks for your interest in improving Aegis. This project takes security and
evidence seriously — every detection claim is backed by the benchmark.

## Ground rules

- **New detectors must ship with benchmark fixtures.** Add a labeled `.sol` file
  to `benchmark/fixtures/` (using the `// <yes> <report> CATEGORY` annotation
  style) so the detector's accuracy is measurable.
- **No regex denial-of-service.** All patterns must be bounded. Run
  `aegis benchmark --fetch-smartbugs` and confirm the full scan stays under a
  few seconds.
- **Map findings to frameworks.** Every detector carries an OWASP SC 2026 id,
  a CWE id, and a MITRE technique. See `src/knowledge/frameworks.js`.
- **Be honest about scope.** If a class can't be detected from source, mark it
  out of scope rather than faking coverage.

## Development

```bash
git clone https://github.com/rsh1k/aegis.git
cd aegis
npm install
node index.js audit ./benchmark/fixtures/reentrancy_simple_dao.sol --offline
node index.js benchmark
```

## High-value contributions

1. **Front-running / MEV detector** — currently 0% coverage.
2. **Improved DoS and time-manipulation recall.**
3. **A self-hosted analysis backend** so source never touches a third-party API.
4. **Release signing** (Sigstore/cosign) for supply-chain integrity.

## Pull requests

- One logical change per PR.
- Include before/after benchmark numbers for any detector change.
- Update the README accuracy table if overall metrics move.

## Reporting vulnerabilities

If you find a security issue in Aegis itself (not in a scanned contract), please
open a private security advisory on GitHub rather than a public issue.
