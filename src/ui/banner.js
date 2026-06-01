import chalk from 'chalk';
import boxen from 'boxen';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

export async function banner() {
  // Force color on
  chalk.level = 3;

  const __dirname = dirname(fileURLToPath(import.meta.url));
  let v = '';
  try {
    const pkg = JSON.parse(readFileSync(join(__dirname, '../../package.json'), 'utf8'));
    v = 'v' + pkg.version + ' · ';
  } catch { /* version optional in banner */ }

  const title = [
    '  █████╗ ███████╗ ██████╗ ██╗███████╗',
    ' ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝',
    ' ███████║█████╗  ██║  ███╗██║███████╗',
    ' ██╔══██║██╔══╝  ██║   ██║██║╚════██║',
    ' ██║  ██║███████╗╚██████╔╝██║███████║',
    ' ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝',
  ].map(l => chalk.hex('#00e6b4')(l)).join('\n');

  const subtitle = chalk.hex('#4a5a6a')('  Aegis · AI-powered smart contract security auditor');
  const version  = chalk.hex('#4a5a6a')('  ' + v + 'OWASP SC Top 10 2026 · MITRE · NIST SSDF');

  console.log('\n' + title);
  console.log(subtitle);
  console.log(version + '\n');
}

export function sectionHeader(title) {
  chalk.level = 3;
  const line = chalk.hex('#162030')('─'.repeat(60));
  const label = chalk.hex('#00e6b4').bold(` ${title} `);
  console.log('\n' + chalk.hex('#00e6b4')('┌') + line);
  console.log(chalk.hex('#00e6b4')('│') + label);
  console.log(chalk.hex('#00e6b4')('└') + line);
}

export function severityBadge(sev) {
  chalk.level = 3;
  const map = {
    CRITICAL: chalk.bgHex('#ff4560').white.bold(' CRITICAL '),
    HIGH:     chalk.bgHex('#ffb740').black.bold('   HIGH   '),
    MEDIUM:   chalk.bgHex('#4da6ff').black.bold('  MEDIUM  '),
    LOW:      chalk.bgHex('#4a5a6a').white.bold('   LOW    '),
  };
  return map[sev] || chalk.gray(` ${sev} `);
}

export function scoreBar(score, width = 30) {
  chalk.level = 3;
  const filled = Math.round((score / 100) * width);
  const empty  = width - filled;
  const color  = score >= 75 ? '#00e6b4' : score >= 50 ? '#ffb740' : '#ff4560';
  const bar    = chalk.hex(color)('█'.repeat(filled)) + chalk.hex('#162030')('░'.repeat(empty));
  return `[${bar}] ${chalk.hex(color).bold(score + '/100')}`;
}

export function dim(text) {
  chalk.level = 3;
  return chalk.hex('#4a5a6a')(text);
}

export function success(text) {
  chalk.level = 3;
  return chalk.hex('#00e6b4')('✔ ') + text;
}

export function warn(text) {
  chalk.level = 3;
  return chalk.hex('#ffb740')('⚠ ') + text;
}

export function error(text) {
  chalk.level = 3;
  return chalk.hex('#ff4560')('✖ ') + text;
}

export function info(text) {
  chalk.level = 3;
  return chalk.hex('#4da6ff')('ℹ ') + text;
}
