// ─────────────────────────────────────────────────────────────────────────────
// Taint detector validation harness
// Measures REAL precision/recall of the taint detectors against a human-labeled
// ground-truth set (benchmark/taint-labeled/). Ground truth is declared in each
// file's header — NOT inferred by any AI — so this is a genuine measurement, not
// AI-grading-AI.
//
// Label syntax (first lines of each .sol):
//   // @expect <detectorId> @ <function>   → a true positive that MUST be found
//   // @safe <function>                    → MUST NOT produce any taint finding
//
// Output feeds calibration.js: detectors get measured precision/recall, and are
// marked source:'measured' instead of 'estimated'.
// ─────────────────────────────────────────────────────────────────────────────

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { buildModel } from '../src/analyzers/model.js';
import { resolveInheritance } from '../src/analyzers/inheritance.js';
import { analyzeTaint } from '../src/analyzers/taint.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const LABELED_DIR = path.join(__dirname, 'taint-labeled');

function parseLabels(src) {
  const expects = [];   // {detectorId, fn}
  const safes = [];     // fn names that must be clean
  for (const line of src.split('\n').slice(0, 8)) {
    let m = line.match(/@expect\s+(\S+)\s+@\s+(\S+)/);
    if (m) expects.push({ detectorId: m[1], fn: m[2] });
    m = line.match(/@safe\s+(\S+)/);
    if (m) safes.push(m[1]);
  }
  return { expects, safes };
}

export function validateTaint() {
  if (!fs.existsSync(LABELED_DIR)) return null;
  const files = fs.readdirSync(LABELED_DIR).filter(f => f.endsWith('.sol'));

  // Per-detector tallies
  const perDetector = {};   // id -> {tp, fp, fn}
  const bump = (id, k) => {
    perDetector[id] = perDetector[id] || { tp: 0, fp: 0, fn: 0 };
    perDetector[id][k]++;
  };

  let tpTotal = 0, fpTotal = 0, fnTotal = 0;
  const caseResults = [];

  for (const file of files) {
    const src = fs.readFileSync(path.join(LABELED_DIR, file), 'utf8');
    const { expects, safes } = parseLabels(src);

    let model = buildModel(src);
    if (model.ok) model = resolveInheritance(model);
    const findings = analyzeTaint(model);

    // Index findings by function
    const foundByFn = {};
    for (const f of findings) {
      const fn = f.function;
      (foundByFn[fn] = foundByFn[fn] || []).push(f.detectorId);
    }

    // Check each expected true positive
    for (const exp of expects) {
      const hits = foundByFn[exp.fn] || [];
      if (hits.includes(exp.detectorId)) {
        bump(exp.detectorId, 'tp'); tpTotal++;
        caseResults.push({ file, expect: `${exp.detectorId}@${exp.fn}`, result: 'TP ✓' });
      } else {
        bump(exp.detectorId, 'fn'); fnTotal++;
        caseResults.push({ file, expect: `${exp.detectorId}@${exp.fn}`, result: 'MISS (false negative)' });
      }
    }

    // Check each safe function — ANY taint finding there is a false positive
    for (const safeFn of safes) {
      const hits = foundByFn[safeFn] || [];
      if (hits.length === 0) {
        caseResults.push({ file, expect: `safe:${safeFn}`, result: 'clean ✓' });
      } else {
        for (const id of hits) { bump(id, 'fp'); fpTotal++; }
        caseResults.push({ file, expect: `safe:${safeFn}`, result: `FALSE POSITIVE (${hits.join(',')})` });
      }
    }
  }

  // Compute measured precision/recall per detector
  const measured = {};
  for (const [id, t] of Object.entries(perDetector)) {
    const precision = (t.tp + t.fp) ? t.tp / (t.tp + t.fp) : null;
    const recall = (t.tp + t.fn) ? t.tp / (t.tp + t.fn) : null;
    measured[id] = {
      precision: precision === null ? null : round(precision),
      recall: recall === null ? null : round(recall),
      samples: t.tp + t.fp + t.fn,
      tp: t.tp, fp: t.fp, fn: t.fn,
    };
  }

  const overall = {
    tp: tpTotal, fp: fpTotal, fn: fnTotal,
    precision: (tpTotal + fpTotal) ? round(tpTotal / (tpTotal + fpTotal)) : null,
    recall: (tpTotal + fnTotal) ? round(tpTotal / (tpTotal + fnTotal)) : null,
  };

  return { files: files.length, measured, overall, caseResults };
}

function round(x) { return Math.round(x * 100) / 100; }

// CLI entry when run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const r = validateTaint();
  if (!r) { console.log('No labeled set found.'); process.exit(1); }
  console.log(`\nTaint validation — ${r.files} labeled contracts\n`);
  console.log('Per-detector measured precision/recall:');
  for (const [id, m] of Object.entries(r.measured)) {
    console.log(`  ${id.padEnd(28)} precision=${m.precision ?? 'n/a'}  recall=${m.recall ?? 'n/a'}  (tp:${m.tp} fp:${m.fp} fn:${m.fn})`);
  }
  console.log(`\nOverall: precision=${r.overall.precision} recall=${r.overall.recall} (tp:${r.overall.tp} fp:${r.overall.fp} fn:${r.overall.fn})\n`);
  console.log('Case-by-case:');
  for (const c of r.caseResults) console.log(`  ${c.result.startsWith('TP') || c.result.startsWith('clean') ? '✓' : '✗'} ${c.file.padEnd(28)} ${c.expect.padEnd(36)} ${c.result}`);
}
