// ─────────────────────────────────────────────────────────────────────────────
// Risk scoring — red-team weighted
// Combines severity, exploit likelihood, and attacker cost into a single
// 0-100 security score. Lower attacker cost + higher likelihood = worse score.
// ─────────────────────────────────────────────────────────────────────────────

const SEV_WEIGHT  = { CRITICAL: 40, HIGH: 20, MEDIUM: 8, LOW: 2 };
const COST_FACTOR = { low: 1.0, medium: 0.6, high: 0.3 };

export function computeRiskScore(findings) {
  let penalty = 0;
  for (const f of findings) {
    const base = SEV_WEIGHT[f.severity] ?? 5;
    const likelihood = (f.exploitLikelihood ?? 3) / 5;     // 0.2 - 1.0
    const cost = COST_FACTOR[f.attackerCost] ?? 0.6;
    penalty += base * likelihood * cost;
  }
  const score = Math.max(0, Math.round(100 - penalty));

  const verdict = score >= 80 ? 'ACCEPTABLE RISK'
                : score >= 60 ? 'REMEDIATE BEFORE MAINNET'
                : score >= 35 ? 'HIGH RISK — DO NOT DEPLOY'
                :               'CRITICAL RISK — DO NOT DEPLOY';

  return { score, verdict };
}

// Category breakdown by OWASP family (0-100 each).
export function categoryBreakdown(findings) {
  const families = {
    'Access control':   ['SC01:2026'],
    'Business logic':   ['SC02:2026'],
    'Oracle / pricing': ['SC03:2026', 'SC04:2026'],
    'Input validation': ['SC05:2026'],
    'External calls':   ['SC06:2026'],
    'Arithmetic':       ['SC07:2026', 'SC09:2026'],
    'Reentrancy':       ['SC08:2026'],
    'Upgradeability':   ['SC10:2026'],
  };
  const out = {};
  for (const [label, ids] of Object.entries(families)) {
    const hits = findings.filter(f => ids.includes(f.owasp));
    let penalty = 0;
    for (const f of hits) {
      penalty += (SEV_WEIGHT[f.severity] ?? 5) * ((f.exploitLikelihood ?? 3) / 5);
    }
    out[label] = Math.max(0, Math.round(100 - penalty * 1.5));
  }
  return out;
}

// Red-team attack-path synthesis: which findings chain into a high-impact exploit.
// This is the "think like an APT" lens — single bugs matter less than chains.
export function synthesizeAttackPaths(findings) {
  const paths = [];
  const has = (owasp) => findings.find(f => f.owasp === owasp);

  // Chain 1: oracle manipulation + flash loan = classic DeFi drain
  if (has('SC03:2026') && (has('SC04:2026') || true)) {
    const oracle = has('SC03:2026');
    if (oracle) {
      paths.push({
        name: 'Flash-loan price manipulation drain',
        severity: 'CRITICAL',
        steps: [
          'Attacker takes an uncollateralized flash loan (no capital required).',
          'Uses the loan to skew the manipulable spot price this contract reads.',
          'Triggers under-priced borrow / over-valued collateral in the same tx.',
          'Repays the flash loan and keeps the difference; all atomic, no risk.',
        ],
        mitre: ['T1565', 'T1583'],
        owasp: ['SC03:2026', 'SC04:2026'],
      });
    }
  }

  // Chain 2: unprotected initializer + delegatecall = proxy takeover
  const init = findings.find(f => f.detectorId === 'UP-unprotected-initializer');
  if (init) {
    paths.push({
      name: 'Proxy takeover via unprotected initializer',
      severity: 'CRITICAL',
      steps: [
        'Attacker front-runs or back-runs deployment to call initialize().',
        'Sets themselves as owner/admin of the proxy.',
        'Uses admin rights to upgrade the implementation to a malicious one.',
        'Drains all funds through the attacker-controlled logic.',
      ],
      mitre: ['T1078', 'T1556'],
      owasp: ['SC10:2026', 'SC01:2026'],
    });
  }

  // Chain 3: access control gap + value transfer = direct theft
  const ac = findings.find(f => f.detectorId === 'AC-missing-modifier');
  if (ac) {
    paths.push({
      name: 'Direct fund theft via missing access control',
      severity: 'CRITICAL',
      steps: [
        'Attacker enumerates public/external state-changing functions.',
        'Calls the unprotected privileged function directly (e.g. setOwner, withdraw).',
        'Escalates privileges or transfers funds with no authorization barrier.',
      ],
      mitre: ['T1078'],
      owasp: ['SC01:2026'],
    });
  }

  // Chain 4: reentrancy + value transfer
  const re = findings.find(f => f.detectorId === 'RE-external-before-state');
  if (re) {
    paths.push({
      name: 'Recursive drain via reentrancy',
      severity: 'CRITICAL',
      steps: [
        'Attacker deploys a contract with a malicious fallback/receive.',
        'Calls the vulnerable withdraw; receives value before balance is zeroed.',
        'Fallback re-enters withdraw repeatedly against stale balance.',
        'Loops until the contract is drained.',
      ],
      mitre: ['T1565'],
      owasp: ['SC08:2026'],
    });
  }

  return paths;
}
