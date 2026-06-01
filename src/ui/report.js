import chalk from 'chalk';
import fs from 'fs';
import { severityBadge, scoreBar, sectionHeader, dim, success, warn } from './banner.js';
import { DISCLAIMER, NIST_SSDF } from '../knowledge/frameworks.js';

chalk.level = 3;
const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

function wrap(text, indent = '  ', width = 76) {
  const words = (text || '').split(' ');
  let line = indent; const out = [];
  for (const w of words) {
    if ((line + w).length > width) { out.push(line); line = indent + w + ' '; }
    else line += w + ' ';
  }
  if (line.trim()) out.push(line);
  return out.join('\n');
}

export function renderReport(contractInfo, findings, meta, options) {
  chalk.level = 3;

  if (options.json) {
    console.log(JSON.stringify({ contractInfo: { name: contractInfo.name, address: contractInfo.address }, score: meta.score, verdict: meta.verdict, findings, attackPaths: meta.attackPaths }, null, 2));
    return;
  }

  const verdictColor = meta.score >= 80 ? '#00e6b4' : meta.score >= 60 ? '#ffb740' : '#ff4560';

  sectionHeader('CONTRACT');
  console.log(`  ${chalk.white.bold('Name:')}     ${chalk.hex('#c8d8e8')(contractInfo.name)}`);
  if (contractInfo.address) console.log(`  ${chalk.white.bold('Address:')}  ${chalk.hex('#4da6ff')(contractInfo.address)} (${contractInfo.network})`);
  console.log(`  ${chalk.white.bold('Solidity:')} ${chalk.hex('#c8d8e8')(meta.metrics.solidityVersion)}`);
  console.log(`  ${chalk.white.bold('Files:')}    ${chalk.hex('#c8d8e8')(contractInfo.files?.length ?? 1)}`);

  sectionHeader('RISK SCORE');
  console.log(`\n  ${scoreBar(meta.score)}`);
  console.log(`\n  ${chalk.hex(verdictColor).bold('> ' + meta.verdict)}`);
  if (meta.aiSummary) console.log(`\n${wrap(meta.aiSummary, '  ')}`);

  console.log('');
  for (const [label, val] of Object.entries(meta.breakdown)) {
    const col = val >= 75 ? '#00e6b4' : val >= 50 ? '#ffb740' : '#ff4560';
    const filled = Math.round((val / 100) * 18);
    const bar = chalk.hex(col)('#'.repeat(filled)) + chalk.hex('#162030')('-'.repeat(18 - filled));
    console.log(`  ${chalk.hex('#4a5a6a')(label.padEnd(18))} [${bar}] ${chalk.hex(col).bold(String(val).padStart(3))}`);
  }

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const f of findings) counts[f.severity]++;
  sectionHeader('FINDINGS SUMMARY');
  console.log(
    `  ${chalk.hex('#ff4560').bold(counts.CRITICAL + ' Critical')}   ` +
    `${chalk.hex('#ffb740').bold(counts.HIGH + ' High')}   ` +
    `${chalk.hex('#4da6ff').bold(counts.MEDIUM + ' Medium')}   ` +
    `${chalk.hex('#4a5a6a').bold(counts.LOW + ' Low')}`
  );

  // Multi-AI panel consensus
  if (meta.consensus && meta.consensus.totalScanners > 1) {
    const con = meta.consensus;
    sectionHeader(`AI PANEL CONSENSUS (${con.totalScanners} scanners)`);
    con.scanners.forEach(s =>
      console.log(`  ${chalk.hex('#4da6ff')(s.label.padEnd(28))} ${chalk.hex('#7a90a8')(s.findingCount + ' finding(s)')}`)
    );
    console.log('');
    for (const c of con.clusters.slice(0, 12)) {
      const confColor = c.confidence === 'HIGH' ? '#00e6b4' : c.confidence === 'MEDIUM' ? '#ffb740' : '#7a90a8';
      console.log(`  ${severityBadge(c.severity)}  ${chalk.white(c.title)}`);
      console.log(`     ${chalk.hex(confColor)(c.confidence + ' confidence')} ${dim('·')} ${c.agreement}/${c.totalScanners} scanners agree ${dim('·')} ${chalk.hex('#4da6ff')(c.owasp || '')}`);
      console.log(`     ${dim('flagged by:')} ${c.agreedBy.join(', ')}${c.dissentedBy.length ? chalk.hex('#7a90a8')('   silent: ' + c.dissentedBy.join(', ')) : ''}`);
    }
    console.log('');
    sectionHeader('PANEL DISCUSSION');
    con.discussion.lines.forEach(l => {
      // wrap each discussion line
      const words = l.split(' '); let line = '  • '; const out = [];
      for (const w of words) { if ((line + w).length > 76) { out.push(line); line = '    ' + w + ' '; } else line += w + ' '; }
      if (line.trim()) out.push(line);
      console.log(out.map(x => chalk.hex('#7a90a8')(x)).join('\n'));
    });
  }

  // Attack paths — the red-team lens
  if (meta.attackPaths && meta.attackPaths.length) {
    sectionHeader('ATTACK PATHS (red-team analysis)');
    for (const p of meta.attackPaths) {
      console.log(`\n  ${severityBadge(p.severity)}  ${chalk.white.bold(p.name)}`);
      console.log(`  ${dim('OWASP:')} ${chalk.hex('#4da6ff')(p.owasp.join(', '))}  ${dim('MITRE:')} ${chalk.hex('#4da6ff')(p.mitre.join(', '))}`);
      p.steps.forEach((s, i) => console.log(chalk.hex('#7a90a8')(`    ${i + 1}. ${s}`)));
    }
  }

  if (findings.length) {
    sectionHeader(`FINDINGS  (${findings.length})`);
    const sorted = [...findings].sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));
    for (let i = 0; i < sorted.length; i++) {
      const f = sorted[i];
      console.log(`\n  ${severityBadge(f.severity)}  ${chalk.white.bold(f.title)}`);
      const tags = [f.owasp, f.cwe, f.mitre].filter(Boolean).join('  ');
      if (tags) console.log(`  ${chalk.hex('#4da6ff')(tags)}`);
      console.log(`  ${dim('Location:')} ${f.location || 'n/a'}  ${dim('Detector:')} ${f.source || 'static'}` +
        (f.exploitLikelihood ? `  ${dim('Exploitability:')} ${f.exploitLikelihood}/5  ${dim('Attacker cost:')} ${f.attackerCost}` : ''));
      if (typeof f.precision === 'number') {
        const provColor = f.precisionProvenance === 'measured' ? '#00e6b4' : '#ffb740';
        const provLabel = f.precisionProvenance === 'measured'
          ? `measured, n=${f.precisionSamples}`
          : 'estimated, unvalidated';
        console.log(`  ${dim('Detector precision:')} ${chalk.hex(provColor)((f.precision * 100).toFixed(0) + '%')} ${chalk.hex(provColor)('(' + provLabel + ')')}`);
      }
      console.log('\n' + wrap(f.description, '  '));
      if (f.fix) console.log(`\n  ${chalk.hex('#00e6b4').bold('Fix:')} ${wrap(f.fix, '').trim()}`);
      if (i < sorted.length - 1) console.log('\n  ' + chalk.hex('#162030')('-'.repeat(60)));
    }
  } else {
    console.log('\n  ' + success('No findings from automated detectors.'));
  }

  // NIST SSDF compliance appendix
  sectionHeader('NIST SSDF (SP 800-218) COVERAGE');
  for (const [k, v] of Object.entries(NIST_SSDF)) {
    console.log(`  ${chalk.hex('#00e6b4')(k.padEnd(6))} ${chalk.hex('#7a90a8')(v)}`);
  }

  console.log('\n' + chalk.hex('#162030')('-'.repeat(78)));
  console.log(wrap(DISCLAIMER, '  '));
  console.log(chalk.hex('#162030')('-'.repeat(78)) + '\n');

  if (options.output) {
    saveMarkdown(options.output, contractInfo, findings, meta);
    console.log(success(`Markdown report saved to ${chalk.hex('#4da6ff')(options.output)}\n`));
  }
}

function saveMarkdown(outputPath, contractInfo, findings, meta) {
  const sorted = [...findings].sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const f of findings) counts[f.severity]++;

  const md = `# Aegis Security Report

**Contract:** ${contractInfo.name}
${contractInfo.address ? `**Address:** \`${contractInfo.address}\` (${contractInfo.network})` : ''}
**Solidity:** ${meta.metrics.solidityVersion}
**Date:** ${new Date().toISOString().slice(0, 19)}Z
**Scanner:** Aegis v2.1.0 ${meta.offline ? '(offline mode)' : '(static + Claude AI)'}

---

## Risk Score: ${meta.score}/100 - ${meta.verdict}

${meta.aiSummary || ''}

### Category Breakdown
| Category | Score |
|---|---|
${Object.entries(meta.breakdown).map(([k, v]) => `| ${k} | ${v}/100 |`).join('\n')}

### Findings Summary
| Severity | Count |
|---|---|
| Critical | ${counts.CRITICAL} |
| High | ${counts.HIGH} |
| Medium | ${counts.MEDIUM} |
| Low | ${counts.LOW} |

---

## Attack Paths (Red-Team Analysis)

${(meta.attackPaths || []).map(p => `### ${p.name} (${p.severity})
**OWASP:** ${p.owasp.join(', ')} | **MITRE ATT&CK:** ${p.mitre.join(', ')}

${p.steps.map((s, i) => `${i + 1}. ${s}`).join('\n')}`).join('\n\n') || '_No multi-step attack chains identified._'}

---

## Findings

${sorted.map((f, i) => `### ${i + 1}. [${f.severity}] ${f.title}

| Field | Value |
|---|---|
| OWASP | ${f.owasp || 'n/a'} ${f.owaspTitle ? '- ' + f.owaspTitle : ''} |
| CWE | ${f.cwe || 'n/a'} ${f.cweName ? '- ' + f.cweName : ''} |
| MITRE ATT&CK | ${f.mitre || 'n/a'} ${f.mitreName ? '- ' + f.mitreName : ''} |
| Location | ${f.location || 'n/a'} |
| Exploitability | ${f.exploitLikelihood ? f.exploitLikelihood + '/5' : 'n/a'} |
| Attacker cost | ${f.attackerCost || 'n/a'} |
| Detector | ${f.source === 'static' ? 'Static analysis' : 'Claude AI'} |

${f.description}

**Recommended fix:** ${f.fix}
`).join('\n---\n\n')}

---

## NIST SSDF (SP 800-218) Coverage

${Object.entries(NIST_SSDF).map(([k, v]) => `- **${k}**: ${v}`).join('\n')}

---

## Disclaimer

${DISCLAIMER}
`;
  fs.writeFileSync(outputPath, md, 'utf8');
}
