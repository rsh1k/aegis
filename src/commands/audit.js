import ora from 'ora';
import chalk from 'chalk';
import fs from 'fs';
import { loadConfig, auditAppend } from '../utils/secure-config.js';
import { fetchSource } from '../utils/fetcher.js';
import { runDetectors, gatherMetrics } from '../analyzers/detectors.js';
import { claudeAnalyze } from '../analyzers/claude.js';
import { computeRiskScore, categoryBreakdown, synthesizeAttackPaths } from '../analyzers/risk.js';
import { generateSBOM, generateSARIF, sha256 } from '../output/formats.js';
import { renderReport } from '../ui/report.js';

chalk.level = 3;

export async function auditCommand(target, options) {
  chalk.level = 3;

  const offline = options.offline || false;
  const config  = loadConfig();
  const apiKey  = process.env.ANTHROPIC_API_KEY || config.apiKey;

  if (!offline && !apiKey) {
    console.log('\n' + chalk.hex('#ff4560')('X No API key found.'));
    console.log(chalk.hex('#7a90a8')('  Run ') + chalk.white('aegis config') + chalk.hex('#7a90a8')(', set ANTHROPIC_API_KEY,'));
    console.log(chalk.hex('#7a90a8')('  or use ') + chalk.white('--offline') + chalk.hex('#7a90a8')(' for static detectors only (no source leaves your machine).\n'));
    process.exit(2);
  }

  const spinner = ora({ color: 'cyan' });

  try {
    spinner.start(chalk.hex('#7a90a8')('Fetching contract source...'));
    const contractInfo = await fetchSource(target, options.network);
    const hash = sha256(contractInfo.source);
    spinner.succeed(chalk.hex('#00e6b4')(`Source loaded - ${contractInfo.files.length} file(s) - ${contractInfo.source.length.toLocaleString()} bytes - sha256:${hash.slice(0,12)}`));

    spinner.start(chalk.hex('#7a90a8')('Running OWASP SC Top 10 (2026) static detectors...'));
    const staticFindings = runDetectors(contractInfo.source);
    const metrics = gatherMetrics(contractInfo.source);
    spinner.succeed(chalk.hex('#00e6b4')(`Static analysis complete - ${staticFindings.length} finding(s)`));

    console.log(
      chalk.hex('#4a5a6a')(`  Solidity: ${metrics.solidityVersion}  -  `) +
      chalk.hex('#4a5a6a')(`Functions: ${metrics.functions}  -  `) +
      (metrics.hasAccessControl ? chalk.hex('#00e6b4')('AccessControl OK') : chalk.hex('#ffb740')('No AccessControl')) +
      chalk.hex('#4a5a6a')('  -  ') +
      (metrics.hasReentrancyGuard ? chalk.hex('#00e6b4')('Guard OK') : chalk.hex('#ffb740')('No Guard')) +
      chalk.hex('#4a5a6a')('  -  ') +
      (metrics.usesOracle ? chalk.hex('#ffb740')('Uses oracle') : chalk.hex('#4a5a6a')('No oracle'))
    );

    let aiFindings = [];
    let aiResult = null;

    if (!offline) {
      spinner.start(chalk.hex('#7a90a8')('Claude AI semantic analysis (business logic, economic attacks)...'));
      try {
        aiResult = await claudeAnalyze(contractInfo.source, staticFindings, metrics, apiKey);
        aiFindings = (aiResult.findings ?? []).map(f => ({
          ...f, source: 'claude',
          exploitLikelihood: f.exploitLikelihood ?? 3,
          attackerCost: f.attackerCost ?? 'medium',
        }));
        spinner.succeed(chalk.hex('#00e6b4')(`Claude analysis complete - ${aiFindings.length} semantic finding(s)`));
      } catch (e) {
        spinner.warn(chalk.hex('#ffb740')('Claude analysis unavailable - continuing with static findings only'));
      }
    } else {
      console.log(chalk.hex('#4da6ff')('  i Offline mode: source code never left this machine. Static detectors only.'));
    }

    const deduped = aiFindings.filter(af =>
      !staticFindings.some(sf => (sf.owasp && sf.owasp === af.owasp && sf.severity === af.severity))
    );
    const allFindings = [...staticFindings, ...deduped];

    const { score, verdict } = computeRiskScore(allFindings);
    const breakdown = categoryBreakdown(allFindings);
    const attackPaths = synthesizeAttackPaths(allFindings);

    renderReport(contractInfo, allFindings, { score, verdict, breakdown, attackPaths, metrics, aiSummary: aiResult?.summary, offline }, options);

    if (options.sarif) {
      fs.writeFileSync(options.sarif, JSON.stringify(generateSARIF(contractInfo, allFindings), null, 2));
      console.log(chalk.hex('#00e6b4')('OK ') + `SARIF written to ${chalk.hex('#4da6ff')(options.sarif)}`);
    }
    if (options.sbom) {
      fs.writeFileSync(options.sbom, JSON.stringify(generateSBOM(contractInfo), null, 2));
      console.log(chalk.hex('#00e6b4')('OK ') + `CycloneDX SBOM written to ${chalk.hex('#4da6ff')(options.sbom)}`);
    }

    auditAppend({ type: 'audit', target, findings: allFindings.length, score });

    const counts = countBySeverity(allFindings);
    const failThreshold = options.failOn || 'high';
    const shouldFail =
      (failThreshold === 'critical' && counts.CRITICAL > 0) ||
      (failThreshold === 'high'     && (counts.CRITICAL > 0 || counts.HIGH > 0)) ||
      (failThreshold === 'medium'   && (counts.CRITICAL > 0 || counts.HIGH > 0 || counts.MEDIUM > 0));

    if (shouldFail && options.ci) {
      console.log('\n' + chalk.hex('#ff4560')(`X CI policy: failing build (threshold=${failThreshold}).`) + '\n');
      process.exit(1);
    }
  } catch (err) {
    spinner.fail(chalk.hex('#ff4560')(err.message || 'Unknown error'));
    if (err.response?.status === 401) console.log('\n' + chalk.hex('#7a90a8')('  Invalid API key. Run: ') + chalk.white('aegis config') + '\n');
    process.exit(2);
  }
}

function countBySeverity(findings) {
  const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const f of findings) c[f.severity] = (c[f.severity] || 0) + 1;
  return c;
}
