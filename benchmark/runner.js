// ─────────────────────────────────────────────────────────────────────────────
// Aegis benchmark runner
// Evaluates the static detector engine against labeled vulnerable contracts
// (SmartBugs Curated format). Computes per-category and overall
// precision / recall / F1 / false-negative-rate.
//
// Methodology notes (stated for honesty):
//  - Ground truth = DASP categories marked with "// <yes> <report> CATEGORY".
//  - A contract is a POSITIVE for category C if it carries a <yes> marker for C.
//  - Aegis "detects" C if it emits any OWASP id mapped from C (see mapping.js).
//  - Detection is scored at CONTRACT level per category (not line level), matching
//    how most SmartBugs tool comparisons report (Durieux et al., ICSE 2020).
//  - short_addresses and other are OUT OF SCOPE and excluded from recall.
//  - This measures the STATIC layer only; the Claude AI layer is not benchmarked
//    here because its output is non-deterministic. Real recall in production is
//    >= static-only recall.
// ─────────────────────────────────────────────────────────────────────────────

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { runDetectors } from '../src/analyzers/detectors.js';
import { DASP_TO_OWASP, OUT_OF_SCOPE, DASP_LABELS } from './mapping.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Map a "<report> CATEGORY" token to a DASP key.
const REPORT_TOKEN_TO_DASP = {
  REENTRANCY: 'reentrancy',
  ACCESS_CONTROL: 'access_control',
  ARITHMETIC: 'arithmetic',
  UNCHECKED_LL_CALLS: 'unchecked_low_level_calls',
  UNCHECKED_LOW_LEVEL_CALLS: 'unchecked_low_level_calls',
  DENIAL_OF_SERVICE: 'denial_of_service',
  DOS: 'denial_of_service',
  BAD_RANDOMNESS: 'bad_randomness',
  FRONT_RUNNING: 'front_running',
  TIME_MANIPULATION: 'time_manipulation',
  SHORT_ADDRESSES: 'short_addresses',
  OTHER: 'other',
};

// Extract ground-truth DASP categories from a contract's annotations.
// Falls back to the parent directory name (SmartBugs organizes by category folder).
export function groundTruthCategories(source, filePath) {
  const cats = new Set();
  const re = /\/\/\s*<yes>\s*<report>\s*([A-Z_]+)/g;
  let m;
  while ((m = re.exec(source)) !== null) {
    const dasp = REPORT_TOKEN_TO_DASP[m[1]];
    if (dasp) cats.add(dasp);
  }
  // Directory-name fallback (full SmartBugs layout: dataset/<category>/file.sol)
  if (cats.size === 0 && filePath) {
    const parent = path.basename(path.dirname(filePath));
    if (DASP_TO_OWASP[parent]) cats.add(parent);
  }
  return [...cats];
}

// What categories did Aegis detect for this source?
export function detectedCategories(source) {
  const findings = runDetectors(source);
  const owaspHits = new Set(findings.map(f => f.owasp));
  const detected = new Set();
  for (const [dasp, owaspIds] of Object.entries(DASP_TO_OWASP)) {
    if (owaspIds.some(id => owaspHits.has(id))) detected.add(dasp);
  }
  return { detected: [...detected], findings };
}

// Run the benchmark over a directory of .sol files (recursively).
export function runBenchmark(datasetDir) {
  const files = collectSol(datasetDir);

  // Per-category confusion counts
  const cats = Object.keys(DASP_TO_OWASP).filter(c => !OUT_OF_SCOPE.includes(c));
  const stats = {};
  for (const c of cats) stats[c] = { tp: 0, fn: 0, fp: 0, support: 0 };

  let cleanContracts = 0;
  let cleanFalsePositives = 0;
  const perContract = [];

  for (const file of files) {
    const source = fs.readFileSync(file, 'utf8');
    const truth = groundTruthCategories(source, file).filter(c => !OUT_OF_SCOPE.includes(c));
    const { detected } = detectedCategories(source);
    const detInScope = detected.filter(c => !OUT_OF_SCOPE.includes(c));

    // Clean contract (no ground-truth vulns): measure false positives
    const isClean = truth.length === 0;
    if (isClean) {
      cleanContracts++;
      if (detInScope.length > 0) cleanFalsePositives++;
    }

    for (const c of cats) {
      const isTrue = truth.includes(c);
      const isDet  = detInScope.includes(c);
      if (isTrue)  stats[c].support++;
      if (isTrue && isDet)   stats[c].tp++;
      else if (isTrue && !isDet) stats[c].fn++;
      else if (!isTrue && isDet) stats[c].fp++;
    }

    perContract.push({
      file: path.relative(datasetDir, file),
      truth, detected: detInScope,
      hit: truth.length > 0 && truth.every(c => detInScope.includes(c)),
    });
  }

  // Compute metrics
  const report = { categories: {}, overall: {}, clean: {} };
  let totTP = 0, totFN = 0, totFP = 0, totSupport = 0;

  for (const c of cats) {
    const { tp, fn, fp, support } = stats[c];
    const precision = (tp + fp) ? tp / (tp + fp) : null;
    const recall    = support ? tp / support : null;
    const f1 = (precision && recall) ? (2 * precision * recall) / (precision + recall) : null;
    report.categories[c] = {
      label: DASP_LABELS[c], support, tp, fn, fp,
      precision, recall, f1,
      falseNegativeRate: support ? fn / support : null,
    };
    totTP += tp; totFN += fn; totFP += fp; totSupport += support;
  }

  const microPrecision = (totTP + totFP) ? totTP / (totTP + totFP) : null;
  const microRecall    = totSupport ? totTP / totSupport : null;
  const microF1 = (microPrecision && microRecall)
    ? (2 * microPrecision * microRecall) / (microPrecision + microRecall) : null;

  report.overall = {
    contractsTested: files.length,
    totalVulnInstances: totSupport,
    truePositives: totTP, falseNegatives: totFN, falsePositives: totFP,
    microPrecision, microRecall, microF1,
    falseNegativeRate: totSupport ? totFN / totSupport : null,
  };
  report.clean = {
    cleanContracts,
    cleanFalsePositives,
    falsePositiveRate: cleanContracts ? cleanFalsePositives / cleanContracts : null,
  };
  report.perContract = perContract;
  return report;
}

function collectSol(dir) {
  const out = [];
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir)) {
    const full = path.join(dir, entry);
    const stat = fs.statSync(full);
    if (stat.isDirectory()) out.push(...collectSol(full));
    else if (entry.endsWith('.sol')) out.push(full);
  }
  return out;
}

export const FIXTURES_DIR = path.join(__dirname, 'fixtures');
