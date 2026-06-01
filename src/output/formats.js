// ─────────────────────────────────────────────────────────────────────────────
// Enterprise output formats
//  - SBOM (CycloneDX 1.5) — NIST SSDF PS.3, EO 14028 software supply chain
//  - SARIF 2.1.0 — standard for GitHub Code Scanning / CI ingestion
// ─────────────────────────────────────────────────────────────────────────────

import crypto from 'crypto';

// Generate a CycloneDX SBOM from detected imports / dependencies in the source.
export function generateSBOM(contractInfo) {
  const source = contractInfo.source;

  // Extract Solidity imports (the contract's "dependencies")
  const importRe = /import\s+(?:\{[^}]*\}\s+from\s+)?["']([^"']+)["']/g;
  const deps = new Set();
  let m;
  while ((m = importRe.exec(source)) !== null) deps.add(m[1]);

  // Detect well-known library families
  const libraries = [];
  if (/@openzeppelin/.test(source)) libraries.push({ name: '@openzeppelin/contracts', purl: 'pkg:npm/@openzeppelin/contracts' });
  if (/@chainlink/.test(source))    libraries.push({ name: '@chainlink/contracts', purl: 'pkg:npm/@chainlink/contracts' });
  if (/@uniswap/.test(source))      libraries.push({ name: '@uniswap/v3-core', purl: 'pkg:npm/@uniswap/v3-core' });
  if (/solmate/.test(source))       libraries.push({ name: 'solmate', purl: 'pkg:github/transmissions11/solmate' });

  const components = [
    ...[...deps].map(d => ({
      type: 'library',
      name: d,
      scope: 'required',
      hashes: [{ alg: 'SHA-256', content: sha256(d) }],
    })),
    ...libraries.map(l => ({
      type: 'library',
      name: l.name,
      purl: l.purl,
      scope: 'required',
    })),
  ];

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ vendor: 'Aegis', name: 'aegis-audit', version: '2.1.0' }],
      component: {
        type: 'application',
        name: contractInfo.name,
        ...(contractInfo.address && { 'bom-ref': contractInfo.address }),
        hashes: [{ alg: 'SHA-256', content: sha256(source) }],
      },
    },
    components,
  };
}

// Convert findings to SARIF 2.1.0 for CI ingestion (GitHub Code Scanning, etc.)
export function generateSARIF(contractInfo, findings) {
  const rules = [];
  const seenRules = new Set();
  const results = [];

  const sarifLevel = { CRITICAL: 'error', HIGH: 'error', MEDIUM: 'warning', LOW: 'note' };

  for (const f of findings) {
    const ruleId = f.detectorId || f.owasp || f.title.slice(0, 24).replace(/\s+/g, '-');
    if (!seenRules.has(ruleId)) {
      seenRules.add(ruleId);
      rules.push({
        id: ruleId,
        name: f.title,
        shortDescription: { text: f.title },
        fullDescription: { text: f.description },
        helpUri: f.owasp ? `https://owasp.org/www-project-smart-contract-top-10/` : undefined,
        properties: {
          tags: [f.owasp, f.cwe, f.mitre].filter(Boolean),
          'security-severity': severityScore(f.severity),
        },
        defaultConfiguration: { level: sarifLevel[f.severity] || 'warning' },
      });
    }

    const lineMatch = /Line (\d+)/.exec(f.location || '');
    results.push({
      ruleId,
      level: sarifLevel[f.severity] || 'warning',
      message: { text: `${f.description}\n\nFix: ${f.fix}` },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: contractInfo.files?.[0]?.name || contractInfo.name },
          region: lineMatch ? { startLine: parseInt(lineMatch[1], 10) } : { startLine: 1 },
        },
      }],
      properties: {
        owasp: f.owasp, cwe: f.cwe, mitre: f.mitre,
        exploitLikelihood: f.exploitLikelihood, attackerCost: f.attackerCost,
      },
    });
  }

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: {
        name: 'Aegis',
        version: '2.1.0',
        informationUri: 'https://github.com/rsh1k/aegis',
        rules,
      }},
      results,
    }],
  };
}

function severityScore(sev) {
  return ({ CRITICAL: '9.5', HIGH: '7.5', MEDIUM: '5.0', LOW: '2.5' })[sev] || '5.0';
}

export function sha256(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}
