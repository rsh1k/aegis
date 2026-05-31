# SolGuard Benchmark

Measures the accuracy of SolGuard's **static detector layer** against labeled
vulnerable contracts, so claims about detection are evidence-based, not asserted.

## Run it

```bash
# Quick run against the 7 built-in labeled fixtures (offline, no deps)
solguard benchmark

# Full academic benchmark: clone & score SmartBugs Curated (143 contracts)
solguard benchmark --fetch-smartbugs

# Your own labeled dataset
solguard benchmark --dataset ./my-labeled-contracts/

# Machine-readable output for CI dashboards
solguard benchmark --fetch-smartbugs --output benchmark.json
```

## Dataset

The full benchmark uses [SmartBugs Curated](https://github.com/smartbugs/smartbugs-curated)
— the academic standard, 143 contracts with 208 tagged vulnerabilities across 10
DASP categories. It was used to compare 9 analysis tools in the ICSE 2020 study
(Durieux et al.).

Ground-truth labels are read from the dataset's own annotations:
`// <yes> <report> CATEGORY` markers, falling back to the category folder name.

## How scoring works

- **Positive** for category C = contract carries a `<yes>` marker for C.
- **Detection** of C = SolGuard emits any OWASP SC 2026 id mapped from C (see `mapping.js`).
- Scoring is **contract-level per category**, matching how SmartBugs tool
  comparisons report.
- We compute, per category and overall: precision, recall, F1, and
  false-negative rate.
- A separate **clean-contract false-positive rate** is measured against
  contracts with no `<yes>` markers.

## Honest scope limits

- **Static layer only.** The Claude AI semantic layer is non-deterministic and is
  not scored here. Real production recall is *higher* than these numbers — but the
  static floor is what you can rely on deterministically.
- **Out of scope:** `short_addresses` (an ABI/calldata-level issue not visible in
  source) and `other` (unspecified) are excluded from recall so the tool isn't
  credited or penalized for classes it doesn't claim to cover.
- **Precision on tiny fixture sets is pessimistic** because vulnerable fixtures
  often contain multiple real issues but are labeled for only one category; the
  extra true findings count against precision. This evens out on the full dataset.

## What good numbers look like

A non-zero false-negative rate is expected and is the entire reason this tool
must not be the only gate before deploying high-value contracts. The benchmark
exists to quantify that gap, not to hide it. Track recall over time as detectors
improve; treat any regression as a release blocker.

## Baseline results (static layer, SmartBugs Curated, 143 contracts)

Measured with `solguard benchmark --fetch-smartbugs`. These are the deterministic
static-layer numbers; the Claude AI layer adds further semantic recall on top.

| Category | Support | Recall | Precision |
|---|---|---|---|
| Reentrancy | 31 | 51.6% | 94.1% |
| Access Control | 18 | 50.0% | 30.0% |
| Arithmetic | 15 | 93.3% | 10.2%* |
| Unchecked Low-Level Calls | 52 | 76.9% | 61.5% |
| Denial of Service | 6 | 33.3% | 8.0% |
| Bad Randomness | 8 | 50.0% | 16.0% |
| Front Running | 4 | 0.0%** | 0.0% |
| Time Manipulation | 5 | 40.0% | 8.0% |
| **Overall (micro)** | **139** | **62.6%** | **24.9%** |

\* Arithmetic precision is depressed because most pre-0.8 contracts trip the
overflow detector broadly; on modern 0.8+ code this is far lower noise.
\** No dedicated front-running detector exists yet — scored honestly as 0.

For comparison, the ICSE 2020 study (Durieux et al.) found that individual
mature tools (Slither, Mythril, etc.) each detected only a fraction of the
dataset, which is why running multiple tools — plus a human audit — is the
recommended practice. SolGuard is one layer in that stack, not a replacement
for it.

### Known gaps (tracked for improvement)
- No front-running / MEV detector.
- DoS and time-manipulation recall are low; detectors need refinement.
- Precision is noisy on legacy Solidity; modern-code precision is higher.
- Performance: all detectors are bounded to avoid regex DoS — full 143-contract
  scan runs in under 1 second.
