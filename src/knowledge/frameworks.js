// ─────────────────────────────────────────────────────────────────────────────
// Aegis knowledge base
// Maps every detector to authoritative framework identifiers so findings are
// traceable to OWASP SC Top 10 (2026), MITRE ATT&CK, and CWE.
//
// Sources:
//  - OWASP Smart Contract Top 10 : 2026 (owasp.org/www-project-smart-contract-top-10)
//  - MITRE ATT&CK v18
//  - MITRE CWE
// ─────────────────────────────────────────────────────────────────────────────

// OWASP Smart Contract Top 10 — 2026 (forward-looking, built on 2025 incident data)
export const OWASP_SC_2026 = {
  SC01: { id: 'SC01:2026', title: 'Access Control Vulnerabilities',
    desc: 'Unauthorized users or roles invoke privileged functions or modify critical state, often leading to full protocol compromise when admin, governance, or upgrade paths are exposed.',
    loss2024: '$953.2M' },
  SC02: { id: 'SC02:2026', title: 'Business Logic Vulnerabilities',
    desc: 'Design-level flaws in lending, AMM, reward, or governance logic that break intended economic rules, letting attackers extract value even when low-level checks pass.',
    loss2024: '$63.8M' },
  SC03: { id: 'SC03:2026', title: 'Price Oracle Manipulation',
    desc: 'Weak oracles and unsafe price integrations let attackers skew reference prices, enabling under-collateralized borrowing, unfair liquidations, and mispriced swaps.',
    loss2024: '$8.8M' },
  SC04: { id: 'SC04:2026', title: 'Flash Loan-Facilitated Attacks',
    desc: 'Large uncollateralized flash loans magnify small bugs into large drains via complex multi-step sequences in a single transaction.',
    loss2024: '$33.8M' },
  SC05: { id: 'SC05:2026', title: 'Lack of Input Validation',
    desc: 'Missing or weak validation of user, admin, or cross-chain inputs allows unsafe parameters to reach core logic, corrupting state or enabling direct fund loss.',
    loss2024: '$14.6M' },
  SC06: { id: 'SC06:2026', title: 'Unchecked External Calls',
    desc: 'Unsafe interactions with external contracts where failures, reverts, or callbacks are not handled, often enabling reentrancy or inconsistent state.',
    loss2024: '$550.7K' },
  SC07: { id: 'SC07:2026', title: 'Arithmetic Errors',
    desc: 'Subtle bugs in integer math, scaling, and rounding — especially in share, interest, and AMM calculations — exploitable for precision loss or value siphoning.',
    loss2024: 'n/a' },
  SC08: { id: 'SC08:2026', title: 'Reentrancy Attacks',
    desc: 'External calls re-enter vulnerable functions before state is updated, allowing repeated withdrawals from an outdated view of state.',
    loss2024: '$35.7M' },
  SC09: { id: 'SC09:2026', title: 'Integer Overflow and Underflow',
    desc: 'Arithmetic on code paths without overflow checks leads to wrapped values, broken invariants, and potential drains.',
    loss2024: 'n/a' },
  SC10: { id: 'SC10:2026', title: 'Proxy & Upgradeability Vulnerabilities',
    desc: 'Misconfigured proxy, initialization, and upgrade mechanisms let attackers seize implementations or reinitialize critical state.',
    loss2024: 'n/a' },
};

// MITRE ATT&CK techniques relevant to smart-contract / Web3 threat modeling.
// On-chain exploitation maps imperfectly to ATT&CK (built for traditional IT),
// so we use the closest applicable techniques plus supply-chain ones that APTs
// (e.g. Lazarus/BlueNoroff G0032) actually use against Web3 teams.
export const MITRE = {
  T1195:    { id: 'T1195',    name: 'Supply Chain Compromise' },
  T1195_001:{ id: 'T1195.001',name: 'Compromise Software Dependencies and Development Tools' },
  T1190:    { id: 'T1190',    name: 'Exploit Public-Facing Application' },
  T1059:    { id: 'T1059',    name: 'Command and Scripting Interpreter' },
  T1499:    { id: 'T1499',    name: 'Endpoint Denial of Service' },
  T1078:    { id: 'T1078',    name: 'Valid Accounts (privileged key abuse)' },
  T1556:    { id: 'T1556',    name: 'Modify Authentication Process' },
  T1565:    { id: 'T1565',    name: 'Data Manipulation (on-chain state/price)' },
  T1583:    { id: 'T1583',    name: 'Acquire Infrastructure (attacker contracts)' },
};

// CWE identifiers for deterministic, tool-agnostic classification.
export const CWE = {
  CWE_284:  { id: 'CWE-284',  name: 'Improper Access Control' },
  CWE_285:  { id: 'CWE-285',  name: 'Improper Authorization' },
  CWE_841:  { id: 'CWE-841',  name: 'Improper Enforcement of Behavioral Workflow' },
  CWE_682:  { id: 'CWE-682',  name: 'Incorrect Calculation' },
  CWE_190:  { id: 'CWE-190',  name: 'Integer Overflow or Wraparound' },
  CWE_191:  { id: 'CWE-191',  name: 'Integer Underflow' },
  CWE_252:  { id: 'CWE-252',  name: 'Unchecked Return Value' },
  CWE_20:   { id: 'CWE-20',   name: 'Improper Input Validation' },
  CWE_362:  { id: 'CWE-362',  name: 'Race Condition' },
  CWE_841b: { id: 'CWE-841',  name: 'Reentrancy' },
  CWE_330:  { id: 'CWE-330',  name: 'Use of Insufficiently Random Values' },
  CWE_400:  { id: 'CWE-400',  name: 'Uncontrolled Resource Consumption' },
  CWE_829:  { id: 'CWE-829',  name: 'Inclusion of Functionality from Untrusted Control Sphere' },
  CWE_665:  { id: 'CWE-665',  name: 'Improper Initialization' },
  CWE_345:  { id: 'CWE-345',  name: 'Insufficient Verification of Data Authenticity' },
};

// NIST SSDF (SP 800-218) practices this tool helps satisfy, for the
// compliance appendix in enterprise reports.
export const NIST_SSDF = {
  'PW.7': 'Review and/or analyze human-readable code to identify vulnerabilities (this scan).',
  'PW.8': 'Test executable code to identify vulnerabilities and verify compliance.',
  'PS.3': 'Archive and protect each software release (SBOM generation).',
  'PS.2': 'Provide a mechanism for verifying software release integrity (signed reports).',
  'RV.1': 'Identify and confirm vulnerabilities on an ongoing basis.',
  'RV.2': 'Assess, prioritize, and remediate vulnerabilities.',
  'RV.3': 'Analyze vulnerabilities to identify their root causes.',
};

export const DISCLAIMER = `Aegis is an AI-assisted automated scanner. It is NOT a substitute for a
professional manual audit, formal verification, or economic/game-theoretic review.
Automated analysis produces both false positives and false negatives. For
high-value or production deployments, commission an independent human audit and,
where applicable, formal verification of critical invariants.`;
