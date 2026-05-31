import axios from 'axios';

export async function claudeAnalyze(source, staticFindings, metrics, apiKey) {
  const staticSummary = staticFindings.length > 0
    ? staticFindings.map(f => `- [${f.severity}] ${f.title} (${f.owasp})`).join('\n')
    : '- None';

  const prompt = `You are an expert Solidity security auditor performing a semantic review that complements automated static analysis. Think like an APT-grade red teamer: focus on business-logic flaws, economic/flash-loan attacks, oracle manipulation, access-control gaps, and centralization risks that pattern matching misses.

CONTRACT SOURCE:
\`\`\`solidity
${source.slice(0, 7000)}${source.length > 7000 ? '\n... [truncated]' : ''}
\`\`\`

CONTEXT:
- Solidity: ${metrics.solidityVersion}
- AccessControl present: ${metrics.hasAccessControl}
- ReentrancyGuard present: ${metrics.hasReentrancyGuard}
- Uses oracle: ${metrics.usesOracle}
- Upgradeable: ${metrics.isUpgradeable}

STATIC ANALYSIS ALREADY FOUND:
${staticSummary}

Find ADDITIONAL issues the static layer missed. Map each to the OWASP Smart Contract Top 10 (2026): SC01 Access Control, SC02 Business Logic, SC03 Price Oracle Manipulation, SC04 Flash Loan, SC05 Input Validation, SC06 Unchecked External Calls, SC07 Arithmetic, SC08 Reentrancy, SC09 Integer Overflow, SC10 Proxy/Upgradeability.

Return ONLY valid JSON (no markdown):
{
  "summary": "<3-4 sentence executive summary written for a security team>",
  "findings": [
    {
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "title": "<short>",
      "location": "<function or line>",
      "owasp": "SC0X:2026",
      "owaspTitle": "<category name>",
      "cwe": "CWE-XXX",
      "cweName": "<name>",
      "mitre": "TXXXX",
      "mitreName": "<technique>",
      "exploitLikelihood": <1-5>,
      "attackerCost": "low|medium|high",
      "description": "<why it's exploitable>",
      "fix": "<concrete remediation>"
    }
  ]
}`;

  const resp = await axios.post(
    'https://api.anthropic.com/v1/messages',
    { model: 'claude-sonnet-4-20250514', max_tokens: 3000, messages: [{ role: 'user', content: prompt }] },
    { headers: { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' }, timeout: 90000 }
  );

  const text = resp.data.content?.[0]?.text || '{}';
  const clean = text.replace(/```json|```/g, '').trim();
  try {
    return JSON.parse(clean);
  } catch {
    return { summary: 'Semantic analysis completed; output could not be parsed. Manual review recommended.', findings: [] };
  }
}
