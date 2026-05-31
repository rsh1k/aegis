import chalk from 'chalk';
import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { runBenchmark, FIXTURES_DIR } from '../../benchmark/runner.js';
import { sectionHeader, dim } from '../ui/banner.js';

chalk.level = 3;

const SMARTBUGS_REPO = 'https://github.com/smartbugs/smartbugs-curated.git';

export async function benchmarkCommand(options) {
  chalk.level = 3;

  let datasetDir = FIXTURES_DIR;
  let datasetName = 'built-in fixtures (7 contracts)';

  // Use a custom dataset dir if provided
  if (options.dataset) {
    datasetDir = options.dataset;
    datasetName = options.dataset;
    if (!fs.existsSync(datasetDir)) {
      console.log('\n' + chalk.hex('#ff4560')(`X Dataset directory not found: ${datasetDir}`) + '\n');
      process.exit(2);
    }
  }

  // Optionally fetch the full SmartBugs Curated dataset (143 contracts)
  if (options.fetchSmartbugs) {
    const target = path.join(process.cwd(), '.aegis-smartbugs');
    if (!fs.existsSync(target)) {
      console.log(dim('  Cloning SmartBugs Curated (143 labeled contracts)...'));
      try {
        execSync(`git clone --depth 1 ${SMARTBUGS_REPO} "${target}"`, { stdio: 'ignore' });
      } catch {
        console.log('\n' + chalk.hex('#ff4560')('X Failed to clone SmartBugs. Check git + network, then retry.') + '\n');
        process.exit(2);
      }
    }
    datasetDir = path.join(target, 'dataset');
    datasetName = 'SmartBugs Curated (143 labeled contracts, DASP taxonomy)';
  }

  console.log(dim(`\n  Dataset: ${datasetName}`));
  console.log(dim('  Scoring: static detector layer only (deterministic). Contract-level, per DASP category.\n'));

  const report = runBenchmark(datasetDir);

  // ── Per-category table ──────────────────────────────────────────────────
  sectionHeader('PER-CATEGORY RESULTS');
  console.log(
    '  ' +
    chalk.hex('#7a90a8')('Category'.padEnd(26)) +
    chalk.hex('#7a90a8')('Supp'.padStart(5)) +
    chalk.hex('#7a90a8')('TP'.padStart(4)) +
    chalk.hex('#7a90a8')('FN'.padStart(4)) +
    chalk.hex('#7a90a8')('FP'.padStart(4)) +
    chalk.hex('#7a90a8')('Recall'.padStart(9)) +
    chalk.hex('#7a90a8')('Prec'.padStart(8)) +
    chalk.hex('#7a90a8')('F1'.padStart(8))
  );
  console.log('  ' + chalk.hex('#162030')('-'.repeat(66)));

  for (const [cat, m] of Object.entries(report.categories)) {
    if (m.support === 0) continue;
    const recall = pct(m.recall);
    const recColor = m.recall >= 0.8 ? '#00e6b4' : m.recall >= 0.5 ? '#ffb740' : '#ff4560';
    console.log(
      '  ' +
      chalk.hex('#c8d8e8')(m.label.slice(0, 25).padEnd(26)) +
      chalk.hex('#c8d8e8')(String(m.support).padStart(5)) +
      chalk.hex('#00e6b4')(String(m.tp).padStart(4)) +
      chalk.hex('#ff4560')(String(m.fn).padStart(4)) +
      chalk.hex('#ffb740')(String(m.fp).padStart(4)) +
      chalk.hex(recColor)(recall.padStart(9)) +
      chalk.hex('#c8d8e8')(pct(m.precision).padStart(8)) +
      chalk.hex('#c8d8e8')(pct(m.f1).padStart(8))
    );
  }

  // ── Overall ─────────────────────────────────────────────────────────────
  sectionHeader('OVERALL (micro-averaged)');
  const o = report.overall;
  const recColor = o.microRecall >= 0.8 ? '#00e6b4' : o.microRecall >= 0.5 ? '#ffb740' : '#ff4560';
  console.log(`  ${chalk.white.bold('Contracts tested:')}      ${o.contractsTested}`);
  console.log(`  ${chalk.white.bold('Vuln instances:')}        ${o.totalVulnInstances}`);
  console.log(`  ${chalk.white.bold('True positives:')}        ${chalk.hex('#00e6b4')(o.truePositives)}`);
  console.log(`  ${chalk.white.bold('False negatives:')}       ${chalk.hex('#ff4560')(o.falseNegatives)}  ${dim('(missed vulnerabilities)')}`);
  console.log(`  ${chalk.white.bold('False positives:')}       ${chalk.hex('#ffb740')(o.falsePositives)}`);
  console.log('');
  console.log(`  ${chalk.white.bold('Recall:')}               ${chalk.hex(recColor).bold(pct(o.microRecall))}  ${dim('(detection rate)')}`);
  console.log(`  ${chalk.white.bold('Precision:')}            ${chalk.hex('#c8d8e8').bold(pct(o.microPrecision))}`);
  console.log(`  ${chalk.white.bold('F1 score:')}             ${chalk.hex('#c8d8e8').bold(pct(o.microF1))}`);
  console.log(`  ${chalk.white.bold('False-negative rate:')}  ${chalk.hex('#ff4560').bold(pct(o.falseNegativeRate))}`);

  // ── Clean-contract false positives ──────────────────────────────────────
  if (report.clean.cleanContracts > 0) {
    sectionHeader('FALSE-POSITIVE CHECK (clean contracts)');
    const fpColor = report.clean.falsePositiveRate <= 0.2 ? '#00e6b4' : '#ffb740';
    console.log(`  ${chalk.white.bold('Clean contracts:')}      ${report.clean.cleanContracts}`);
    console.log(`  ${chalk.white.bold('Flagged anyway:')}       ${chalk.hex(fpColor)(report.clean.cleanFalsePositives)}`);
    console.log(`  ${chalk.white.bold('False-positive rate:')}  ${chalk.hex(fpColor).bold(pct(report.clean.falsePositiveRate))}`);
  }

  // ── Honesty footer ──────────────────────────────────────────────────────
  console.log('\n' + chalk.hex('#162030')('-'.repeat(72)));
  console.log(dim('  These numbers reflect the deterministic static layer only. The Claude AI'));
  console.log(dim('  layer adds semantic findings not measured here, so production recall is'));
  console.log(dim('  higher — but a non-zero false-negative rate means this tool MUST NOT be'));
  console.log(dim('  the only gate before deploying high-value contracts.'));
  console.log(chalk.hex('#162030')('-'.repeat(72)) + '\n');

  // ── Machine-readable output ─────────────────────────────────────────────
  if (options.output) {
    fs.writeFileSync(options.output, JSON.stringify(report, null, 2));
    console.log(chalk.hex('#00e6b4')('OK ') + `Full benchmark report written to ${chalk.hex('#4da6ff')(options.output)}\n`);
  }
}

function pct(x) {
  if (x === null || x === undefined) return 'n/a';
  return (x * 100).toFixed(1) + '%';
}
