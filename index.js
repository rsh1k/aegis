#!/usr/bin/env node
import { program } from 'commander';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { auditCommand } from './src/commands/audit.js';
import { configCommand } from './src/commands/config.js';
import { benchmarkCommand } from './src/commands/benchmark.js';
import { banner } from './src/ui/banner.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(join(__dirname, 'package.json'), 'utf8'));

await banner();

program
  .name('aegis')
  .description('AI-powered smart contract security auditor - OWASP SC Top 10 (2026), MITRE, NIST SSDF')
  .version(pkg.version);

program
  .command('audit <target>')
  .description('Audit a contract by address, .sol file, or folder')
  .option('-n, --network <network>', 'network (ethereum|base|arbitrum|polygon|optimism|bsc)', 'ethereum')
  .option('-o, --output <path>', 'save markdown report (e.g. report.md)')
  .option('--sarif <path>', 'write SARIF 2.1.0 for CI ingestion (e.g. results.sarif)')
  .option('--sbom <path>', 'write CycloneDX SBOM (NIST SSDF PS.3)')
  .option('--offline', 'static detectors only; source code never leaves your machine')
  .option('--ci', 'CI mode: exit non-zero when findings breach --fail-on threshold')
  .option('--fail-on <level>', 'CI fail threshold (critical|high|medium)', 'high')
  .option('--json', 'machine-readable JSON output')
  .action(auditCommand);

program
  .command('config')
  .description('Set encrypted API key and verify audit-log integrity')
  .action(configCommand);

program
  .command('benchmark')
  .description('Measure detector accuracy against labeled vulnerable contracts')
  .option('--dataset <dir>', 'custom dataset directory of labeled .sol files')
  .option('--fetch-smartbugs', 'clone & use SmartBugs Curated (143 contracts)')
  .option('-o, --output <path>', 'write full JSON benchmark report')
  .action(benchmarkCommand);

program.parse();
