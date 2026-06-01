<div align="center">

# 🛡️ Aegis

### AI-Powered Smart Contract Security Auditor

*Detect vulnerabilities before attackers do — mapped to OWASP, MITRE ATT&CK, CWE & NIST.*

[![License: MIT](https://img.shields.io/badge/License-MIT-00e6b4.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D18-339933.svg)](https://nodejs.org)
[![OWASP SC Top 10](https://img.shields.io/badge/OWASP-SC%20Top%2010%20(2026)-185fa5.svg)](https://owasp.org/www-project-smart-contract-top-10/)
[![Benchmarked](https://img.shields.io/badge/benchmark-SmartBugs%20Curated-854f0b.svg)](benchmark/README.md)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-00e6b4.svg)](CONTRIBUTING.md)

</div>

---

Aegis is a command-line security auditor for Solidity smart contracts. It combines a deterministic static-analysis engine with an AI semantic layer, maps every finding to industry frameworks, and produces enterprise-grade compliance artifacts (SARIF, SBOM, signed audit logs). Its detection accuracy is measured against an academic benchmark — not asserted.

```bash
npm install -g aegis-audit
aegis audit ./contracts/MyToken.sol
```

## Why Aegis

Most scanners hand you a list of bugs. Aegis is built for teams that ship to production:

- **Full OWASP SC Top 10 (2026) coverage** — including the categories that actually cause losses. Access control alone was $953M of $1.42B in 2024 losses, far ahead of reentrancy.
- **Framework traceability** — every finding carries its `SC0X:2026`, `CWE-XXX`, and MITRE `TXXXX` identifiers for audit and compliance reporting.
- **Red-team attack-path synthesis** — chains individual findings into the multi-step exploits an APT would actually run (flash-loan price manipulation, proxy takeover, recursive drain).
- **Offline mode** — `--offline` runs all static detectors without your source code ever leaving the machine. Built for proprietary and regulated codebases.
- **CI/CD native** — SARIF 2.1.0 output, configurable fail thresholds, proper exit codes.
- **NIST SSDF (SP 800-218) outputs** — CycloneDX SBOM generation, encrypted key storage, and a tamper-evident hash-chained audit log.
- **Measured, not claimed** — ships with a benchmark harness scored against the SmartBugs Curated dataset.

## Install

```bash
npm install -g aegis-audit
aegis config        # set encrypted API key (or use --offline)
```

Get a free Anthropic API key at [console.anthropic.com](https://console.anthropic.com). Enterprises should prefer setting `ANTHROPIC_API_KEY` via a secrets manager, or use `--offline`.

## Usage

```bash
# Audit a local file, a folder, or a verified on-chain address
aegis audit ./contracts/MyToken.sol
aegis audit ./contracts/
aegis audit 0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984 --network ethereum

# Enterprise / regulated: never transmit source code
aegis audit ./contracts/ --offline

# Generate compliance + CI artifacts
aegis audit ./contracts/ --sarif results.sarif --sbom sbom.json --output report.md

# CI gate (non-zero exit on high+ findings)
aegis audit ./contracts/ --ci --fail-on high

# Measure detector accuracy against labeled datasets
aegis benchmark
aegis benchmark --fetch-smartbugs
```

## What it detects — OWASP Smart Contract Top 10 (2026)

| ID | Category | Detectors |
|----|----------|-----------|
| SC01 | Access Control | Missing modifiers, `tx.origin` auth, unprotected `selfdestruct` |
| SC02 | Business Logic | Precision loss, unbounded loops (DoS), weak randomness, timestamp logic |
| SC03 | Price Oracle Manipulation | Spot-price-as-oracle detection |
| SC04 | Flash Loan | Callback-invariant flags |
| SC05 | Input Validation | Missing zero-address checks |
| SC06 | Unchecked External Calls | Unchecked `.call`, unsafe ERC20 transfer |
| SC07 / SC09 | Arithmetic / Overflow | Pre-0.8 Solidity, `unchecked` blocks |
| SC08 | Reentrancy | External-call-before-state, missing guards |
| SC10 | Proxy & Upgradeability | Unprotected initializer, `delegatecall` |

Plus a **Claude AI semantic layer** for business-logic and economic attacks that pattern matching misses.

## Accuracy

Aegis ships with a benchmark harness so detection is evidence-based. On the academic [SmartBugs Curated](https://github.com/smartbugs/smartbugs-curated) dataset (143 labeled contracts), the deterministic static layer alone scores:

| Metric | Value |
|--------|-------|
| Overall recall | 62.6% |
| Reentrancy precision | 94.1% |
| Unchecked-call recall | 76.9% |
| Full-dataset scan time | < 1 second |

The AI layer adds semantic recall on top of this floor. Full per-category numbers and methodology are in [`benchmark/README.md`](benchmark/README.md). For comparison, the ICSE 2020 study found individual mature tools each detect only a fraction of the dataset — which is why running multiple tools, plus a human audit, is the recommended practice.

## CI example (GitHub Actions)

```yaml
- name: Aegis audit
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
  run: |
    npm install -g aegis-audit
    aegis audit ./contracts/ --ci --fail-on high --sarif results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Security & threat model

This tool is itself part of your software supply chain. State-sponsored groups (e.g. Lazarus/BlueNoroff, MITRE G0032) actively target Web3 developer toolchains via malicious packages (T1195). Accordingly:

- API keys are encrypted at rest (AES-256-GCM); enterprises should prefer a secrets manager.
- `--offline` guarantees no source transmission.
- The audit log is append-only and hash-chained — any edit to history is detectable via `aegis config`.
- All detector patterns are bounded against regex denial-of-service.

## Disclaimer

Aegis is an AI-assisted automated scanner. It is **not** a substitute for a professional manual audit, formal verification, or economic review. Automated analysis produces both false positives and false negatives. For high-value or production deployments, commission an independent human audit and, where applicable, formal verification of critical invariants.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). The most valuable contributions right now are new detectors (front-running/MEV, improved DoS) with corresponding benchmark fixtures.

## License

[MIT](LICENSE) © 2026 rsh1k
