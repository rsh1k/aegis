import ora from 'ora';
import chalk from 'chalk';
import fs from 'fs';
import { loadConfig, auditAppend } from '../utils/secure-config.js';
import { fetchSource } from '../utils/fetcher.js';
import { runDetectors, gatherMetrics } from '../analyzers/detectors.js';
import { buildModel } from '../analyzers/model.js';
import { runSemanticDetectors, runContractChecks } from '../analyzers/semantic.js';
import { analyzeTaint } from '../analyzers/taint.js';
import { resolveInheritance } from '../analyzers/inheritance.js';
import { calibrateAll } from '../analyzers/calibration.js';
import { smtCheck, generateInvariants } from '../analyzers/external-tools.js';
import { claudeAnalyze } from '../analyzers/claude.js';
import { runPanel, listOllamaModels } from '../analyzers/providers.js';
import { adjudicate } from '../analyzers/consensus.js';
import { resolveProviders } from './provider-config.js';
import { computeRiskScore, categoryBreakdown, synthesizeAttackPaths } from '../analyzers/risk.js';
import { generateSBOM, generateSARIF, sha256 } from '../output/formats.js';
import { renderReport } from '../ui/report.js';

chalk.level = 3;

export async function auditCommand(target, options) {
  chalk.level = 3;

  const offline = options.offline || false;
  const usingPanel = !!(options.panel || options.provider);
  const config  = loadConfig();
  const apiKey  = process.env.ANTHROPIC_API_KEY || config.apiKey;

  // Panel mode resolves its own provider keys; only the single-model path needs
  // a key here. Offline needs none.
  if (!offline && !usingPanel && !apiKey) {
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

    spinner.start(chalk.hex('#7a90a8')('Building semantic model (AST, call graph, data flow)...'));
    let model = buildModel(contractInfo.source);
    if (model.ok) model = resolveInheritance(model);   // flatten base-contract guards
    let staticFindings;
    let analysisMode;

    if (model.ok && model.contracts.length > 0) {
      const semantic = [...runSemanticDetectors(model), ...runContractChecks(model, contractInfo.source)];
      const taint = analyzeTaint(model);                // cross-function taint flows
      const regex = runDetectors(contractInfo.source);

      const semKeys = new Set([...semantic, ...taint].map(f => `${f.owasp}`));
      const regexFiltered = regex.filter(rf => !semKeys.has(rf.owasp));

      staticFindings = [...semantic, ...taint, ...regexFiltered];
      analysisMode = `semantic+taint+pattern (${semantic.length} sem, ${taint.length} taint, ${regexFiltered.length} pattern)`;
      spinner.succeed(chalk.hex('#00e6b4')(`Hybrid analysis complete - ${staticFindings.length} finding(s) across ${model.contracts.length} contract(s)`));
    } else {
      staticFindings = runDetectors(contractInfo.source);
      analysisMode = 'pattern (parse failed, fell back)';
      spinner.warn(chalk.hex('#ffb740')(`AST parse failed - using pattern fallback - ${staticFindings.length} finding(s)`));
    }

    // Confidence calibration — attach empirical precision per detector
    staticFindings = calibrateAll(staticFindings);

    // Optional formal verification via solc SMTChecker (tier 5)
    if (options.formal) {
      spinner.start(chalk.hex('#7a90a8')('Running formal verification (solc SMTChecker)...'));
      const smt = await smtCheck(contractInfo.source, contractInfo.name);
      if (smt.available) {
        staticFindings = [...staticFindings, ...calibrateAll(smt.findings)];
        spinner.succeed(chalk.hex('#00e6b4')(`Formal verification complete - ${smt.findings.length} formal finding(s)`));
      } else {
        spinner.warn(chalk.hex('#ffb740')('solc not found - skipping formal verification (install solc to enable --formal)'));
      }
    }

    // Optional fuzz invariant scaffold generation (tier 4)
    if (options.fuzz && model.ok) {
      const inv = generateInvariants(model, contractInfo.name);
      if (inv) {
        const fp = `${contractInfo.name || 'contract'}Invariants.t.sol`;
        const ep = `${contractInfo.name || 'contract'}Echidna.sol`;
        fs.writeFileSync(fp, inv.foundryFile);
        fs.writeFileSync(ep, inv.echidnaFile);
        console.log(chalk.hex('#00e6b4')('OK ') + `Generated ${inv.invariantCount} invariant(s): ${chalk.hex('#4da6ff')(fp)}, ${chalk.hex('#4da6ff')(ep)}`);
      }
    }

    const metrics = gatherMetrics(contractInfo.source);

    const fnCount = model.ok ? model.contracts.reduce((n, c) => n + c.functions.length, 0) : metrics.functions;
    console.log(
      chalk.hex('#4a5a6a')(`  Solidity: ${metrics.solidityVersion}  -  `) +
      chalk.hex('#4a5a6a')(`Functions: ${fnCount}  -  Mode: ${analysisMode}`)
    );

    let aiFindings = [];
    let aiResult = null;
    let consensus = null;

    if (!offline && (options.panel || options.provider)) {
      // ── Multi-AI panel mode ──────────────────────────────────────────────
      let providers = resolveProviders({ panel: options.panel, providerList: options.provider, model: options.model });

      // Auto-detect the Ollama model when none was specified: ask Ollama what's
      // actually installed and use the first available, rather than guessing a name.
      for (const p of providers) {
        if (p.type === 'ollama' && !p.model) {
          const available = await listOllamaModels(p.baseURL);
          if (available.length > 0) {
            p.model = available[0];
            p.label = `Ollama (local: ${p.model})`;
            if (available.length > 1) {
              console.log(chalk.hex('#4a5a6a')(`  i Using Ollama model "${p.model}". Others available: ${available.slice(1).join(', ')}. Pick one with --model.`));
            }
          } else {
            p.label = 'Ollama (local: none found)';
          }
        } else if (p.type === 'ollama') {
          p.label = `Ollama (local: ${p.model})`;
        }
      }

      if (providers.length === 0) {
        spinner.warn(chalk.hex('#ffb740')('No AI providers have keys configured. Run "aegis config" or set ANTHROPIC_API_KEY / OPENAI_API_KEY.'));
      } else {
        spinner.start(chalk.hex('#7a90a8')(`Running AI panel: ${providers.map(p => p.label).join(', ')}...`));
        const panelResults = await runPanel(providers, { source: contractInfo.source, staticFindings, metrics });
        const okCount = panelResults.filter(r => r.ok).length;
        const failed = panelResults.filter(r => !r.ok);
        spinner.succeed(chalk.hex('#00e6b4')(`Panel complete - ${okCount}/${providers.length} provider(s) responded`));
        for (const f of failed) console.log(chalk.hex('#ffb740')(`  ⚠ ${f.label}: ${f.error}`));

        consensus = adjudicate(panelResults, staticFindings);

        // Promote high/medium-confidence consensus clusters into findings
        aiFindings = consensus.clusters
          .filter(c => c.agreement >= 1 && !staticFindings.some(sf => sf.owasp === c.owasp && String(sf.location || '').toLowerCase().includes((c.function || '').toLowerCase())))
          .map(c => ({
            severity: c.severity,
            title: c.title,
            location: `${contractInfo.name || 'contract'}.${c.function}`,
            function: c.function,
            owasp: c.owasp, owaspTitle: '', cwe: null, mitre: null,
            description: (c.details[0]?.text || '') + ` [consensus: ${c.agreement}/${c.totalScanners} scanners, ${c.confidence} confidence]`,
            fix: c.fixes[0] || 'See provider detail.',
            exploitLikelihood: c.severity === 'CRITICAL' ? 5 : c.severity === 'HIGH' ? 4 : 3,
            attackerCost: 'low',
            source: 'panel',
            confidence: c.confidence,
          }));
      }
    } else if (!offline) {
      // ── Single-model mode (back-compat) ──────────────────────────────────
      spinner.start(chalk.hex('#7a90a8')('Claude AI deep review (business logic, economic attacks)...'));
      try {
        aiResult = await claudeAnalyze(contractInfo.source, staticFindings, metrics, apiKey);
        aiFindings = (aiResult.findings ?? []).map(f => ({
          ...f, source: 'claude',
          exploitLikelihood: f.exploitLikelihood ?? 3,
          attackerCost: f.attackerCost ?? 'medium',
        }));
        spinner.succeed(chalk.hex('#00e6b4')(`Claude review complete - ${aiFindings.length} additional finding(s)`));
      } catch (e) {
        spinner.warn(chalk.hex('#ffb740')('Claude review unavailable - continuing with semantic findings only'));
      }
    } else {
      console.log(chalk.hex('#4da6ff')('  i Offline mode: source code never left this machine. Semantic analysis only.'));
    }

    const deduped = aiFindings.filter(af =>
      !staticFindings.some(sf => (sf.owasp && sf.owasp === af.owasp && sf.function && af.location && String(af.location).includes(sf.function)))
    );
    const allFindings = [...staticFindings, ...deduped];

    const { score, verdict } = computeRiskScore(allFindings);
    const breakdown = categoryBreakdown(allFindings);
    const attackPaths = synthesizeAttackPaths(allFindings);

    renderReport(contractInfo, allFindings, { score, verdict, breakdown, attackPaths, metrics, aiSummary: aiResult?.summary, offline, consensus }, options);

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
