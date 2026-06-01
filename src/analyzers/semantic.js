// ─────────────────────────────────────────────────────────────────────────────
// Semantic detectors — operate on the contract MODEL, not raw text.
// Each finding includes CVSS-style metrics: attack vector, privileges required,
// exploitability, and whether a mitigating control is already present.
// This context is what lets us suppress false positives and rank by real risk.
//
// CVSS mapping (Base, simplified for smart-contract context):
//   AV: Network (on-chain calls are remotely reachable) = N
//   PR: None (anyone) / Low (token holder) / High (owner/admin)
//   We derive a 0-10 score from severity + privilege + mitigation.
// ─────────────────────────────────────────────────────────────────────────────

import { OWASP_SC_2026 as O, MITRE as M, CWE as C } from '../knowledge/frameworks.js';

// CVSS-ish base score from factors. Not a full CVSS v3.1 vector calc, but uses
// the same dimensions so enterprise teams can map it to their process.
function cvss({ severity, privilegesRequired, hasMitigation, userReachable }) {
  let base = { CRITICAL: 9.0, HIGH: 7.0, MEDIUM: 4.5, LOW: 2.0 }[severity] ?? 4;
  if (privilegesRequired === 'high') base -= 2.5;   // owner-only → harder
  else if (privilegesRequired === 'low') base -= 0.8;
  if (!userReachable) base -= 1.5;                   // not externally reachable
  if (hasMitigation) base -= 2.0;                    // partial control present
  return Math.max(0.1, Math.min(10, Math.round(base * 10) / 10));
}

function cvssSeverity(score) {
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  if (score >= 0.1) return 'LOW';
  return 'NONE';
}

// privilegesRequired: derive from whether the function is access-controlled
function privFor(fn) {
  if (fn.hasAccessControl) return 'high';
  if (fn.visibility === 'internal' || fn.visibility === 'private') return 'high';
  return 'none';
}

function userReachable(fn) {
  return fn.visibility === 'public' || fn.visibility === 'external' || fn.visibility === 'default';
}

function mk(fn, contract, def, extra = {}) {
  const pr = extra.privilegesRequired ?? privFor(fn);
  const reachable = extra.userReachable ?? userReachable(fn);
  const hasMitigation = extra.hasMitigation ?? false;
  const score = cvss({ severity: def.severity, privilegesRequired: pr, hasMitigation, userReachable: reachable });
  const effSeverity = cvssSeverity(score);
  return {
    detectorId: def.id,
    severity: effSeverity,             // severity AFTER context adjustment
    baseSeverity: def.severity,        // raw class severity
    title: def.title,
    location: fn.loc ? `${contract.name}.${fn.name} (line ${fn.loc})` : `${contract.name}.${fn.name}`,
    function: fn.name,
    contract: contract.name,
    description: typeof def.description === 'function' ? def.description(fn, contract) : def.description,
    fix: def.fix,
    owasp: def.owasp.id, owaspTitle: def.owasp.title,
    cwe: def.cwe.id, cweName: def.cwe.name,
    mitre: def.mitre.id, mitreName: def.mitre.name,
    cvss: score,
    cvssVector: `AV:N/PR:${pr === 'none' ? 'N' : pr === 'low' ? 'L' : 'H'}`,
    privilegesRequired: pr,
    userReachable: reachable,
    hasMitigation,
    confidence: extra.confidence ?? def.confidence ?? 'medium',
    source: 'semantic',
  };
}

// ── The detectors ───────────────────────────────────────────────────────────
export function runSemanticDetectors(model) {
  const findings = [];
  if (!model.ok) return findings;

  for (const contract of model.contracts) {
    if (contract.kind === 'interface') continue;

    for (const fn of contract.functions) {

      // SC08 Reentrancy — only when external call precedes state write AND no guard.
      // This is the false-positive killer: we do NOT flag every value transfer.
      if (fn.externalCallBeforeWrite && !fn.hasReentrancyGuard) {
        findings.push(mk(fn, contract, {
          id: 'SEM-reentrancy', severity: 'CRITICAL',
          owasp: O.SC08, cwe: C.CWE_841b, mitre: M.T1565,
          title: 'Reentrancy: external call before state update',
          description: (f) => `Function '${f.name}' makes an external value-bearing call before updating contract state (a balance/share variable is written after the call). With no reentrancy guard present, a malicious recipient can re-enter and repeat the withdrawal against stale state. This is the DAO-class bug.`,
          fix: 'Apply Checks-Effects-Interactions (update state before the external call) AND add OpenZeppelin ReentrancyGuard (nonReentrant).',
        }, { confidence: 'high' }));
      }

      // SC01 Access control — privileged action with NO guard and externally reachable.
      // Context-aware: we skip view/pure, constructors, and guarded fns.
      const privilegedName = /^(set|update|withdraw|mint|burn|upgrade|pause|unpause|grant|revoke|destroy|kill|sweep|rescue|transferOwnership|changeOwner|init|initialize|setOwner)/i.test(fn.name);
      // Self-scoped: every state write targets the caller's own slot (e.g. balances[msg.sender]).
      // Such functions are meant to be open (deposit/withdraw your own funds) and must NOT
      // be flagged for missing access control — this is the key false-positive suppressor.
      const allWritesSelfScoped = fn.stateWrites.length > 0 && fn.stateWrites.every(w => w.selfScoped);
      const mutates = fn.stateWrites.length > 0 || fn.externalCalls.length > 0 || fn.callsSelfdestruct;
      if (privilegedName && mutates && userReachable(fn) && !fn.hasAccessControl
          && !allWritesSelfScoped
          && fn.stateMutability !== 'view' && fn.stateMutability !== 'pure'
          && !fn.isConstructor) {
        // Mitigation: if the function only writes the caller's own mapping slot, lower risk
        findings.push(mk(fn, contract, {
          id: 'SEM-access-control', severity: 'CRITICAL',
          owasp: O.SC01, cwe: C.CWE_284, mitre: M.T1078,
          title: 'Missing access control on privileged function',
          description: (f) => `'${f.name}' performs a privileged, state-changing action and is externally callable with no access-control modifier or msg.sender check. Any address can invoke it. Access-control failures were the largest single loss category in 2024 ($953M).`,
          fix: 'Add onlyOwner / onlyRole(ROLE) or an explicit require(msg.sender == authorized). Prefer OpenZeppelin AccessControl with least-privilege roles.',
        }, { privilegesRequired: 'none' }));
      }

      // SC10 Unprotected initializer — initialize() reachable, upgradeable, no guard
      if (/^initialize$/i.test(fn.name) && userReachable(fn) && !fn.hasAccessControl
          && !fn.modifiers.some(m => /^(initializer|reinitializer)$/i.test(m))) {
        findings.push(mk(fn, contract, {
          id: 'SEM-init', severity: 'CRITICAL',
          owasp: O.SC10, cwe: C.CWE_665, mitre: M.T1078,
          title: 'Unprotected initializer (proxy takeover risk)',
          description: () => `'initialize' is externally callable without the initializer modifier or access control. On a proxy pattern an attacker can call it post-deployment to seize ownership.`,
          fix: 'Use OpenZeppelin Initializable with the initializer modifier; call _disableInitializers() in the implementation constructor.',
        }, { privilegesRequired: 'none' }));
      }

      // SC01 tx.origin auth
      if (fn.usesTxOrigin) {
        findings.push(mk(fn, contract, {
          id: 'SEM-tx-origin', severity: 'HIGH',
          owasp: O.SC01, cwe: C.CWE_285, mitre: M.T1556,
          title: 'tx.origin used for authorization',
          description: () => `'${fn.name}' uses tx.origin for an authorization decision. A malicious intermediary contract the owner calls can satisfy this check (phishing).`,
          fix: 'Use msg.sender instead of tx.origin for authorization.',
        }));
      }

      // SC01 unprotected selfdestruct
      if (fn.callsSelfdestruct) {
        const guarded = fn.hasAccessControl;
        findings.push(mk(fn, contract, {
          id: 'SEM-selfdestruct', severity: 'HIGH',
          owasp: O.SC01, cwe: C.CWE_284, mitre: M.T1078,
          title: guarded ? 'selfdestruct present (access-controlled)' : 'Unprotected selfdestruct',
          description: () => `'${fn.name}' can selfdestruct the contract${guarded ? ' (an access-control guard is present, reducing but not eliminating risk — a single compromised key is still catastrophic)' : ' with no access control — any caller can destroy it and sweep funds'}. selfdestruct is deprecated (EIP-6049).`,
          fix: 'Remove selfdestruct if possible. If required, gate behind multi-sig + timelock.',
        }, { hasMitigation: guarded, privilegesRequired: guarded ? 'high' : 'none' }));
      }

      // SC10 delegatecall
      if (fn.callsDelegatecall) {
        findings.push(mk(fn, contract, {
          id: 'SEM-delegatecall', severity: 'HIGH',
          owasp: O.SC10, cwe: C.CWE_829, mitre: M.T1565,
          title: 'delegatecall usage',
          description: () => `'${fn.name}' uses delegatecall, executing external code against this contract's storage. If the target is influenced by input or upgradeable, storage can be hijacked.`,
          fix: 'Restrict delegatecall to immutable, audited implementations; use a vetted proxy pattern with storage-gap discipline.',
        }));
      }

      // SC06 unchecked external call — value-bearing call whose result isn't required
      // (model marks valueBearing; we approximate "unchecked" as a call in a fn that
      //  has an external call but no require referencing it — conservative)
      const hasValueCall = fn.externalCalls.some(c => c.kind === 'call' && c.valueBearing);
      if (hasValueCall && !fn.externalCallBeforeWrite && !fn.inlineSenderCheck && fn.stateWrites.length === 0) {
        findings.push(mk(fn, contract, {
          id: 'SEM-unchecked-call', severity: 'MEDIUM',
          owasp: O.SC06, cwe: C.CWE_252, mitre: M.T1565,
          title: 'Low-level call return value may be unchecked',
          description: () => `'${fn.name}' makes a low-level value call. Confirm the boolean return is checked with require; some failures are silent otherwise.`,
          fix: 'Capture and require the return: (bool ok,) = target.call{...}(...); require(ok);',
        }, { confidence: 'low' }));
      }

      // SC02 weak randomness
      if (fn.usesBlockProperties && (/random|draw|winner|lottery|roll|pick/i.test(fn.name) || fn.usesBlockTimestamp)) {
        findings.push(mk(fn, contract, {
          id: 'SEM-randomness', severity: 'HIGH',
          owasp: O.SC02, cwe: C.CWE_330, mitre: M.T1565,
          title: 'Insecure on-chain randomness',
          description: () => `'${fn.name}' derives values from block properties (timestamp/difficulty/number). These are validator-influenceable and predictable, breaking any value that depends on unpredictability.`,
          fix: 'Use Chainlink VRF or a commit-reveal scheme for randomness.',
        }));
      }

      // SC09 overflow — only on pre-0.8 with raw multiply and no SafeMath
      if (fn.rawMultiply && !contract.solMajor8Plus && !contract.usesSafeMath
          && fn.stateMutability !== 'view' && fn.stateMutability !== 'pure') {
        findings.push(mk(fn, contract, {
          id: 'SEM-overflow', severity: 'HIGH',
          owasp: O.SC09, cwe: C.CWE_190, mitre: M.T1565,
          title: 'Unchecked multiplication on pre-0.8 Solidity',
          description: () => `'${fn.name}' performs multiplication on a pre-0.8 compiler without SafeMath. A large factor overflows silently (the BeautyChain/BEC class bug).`,
          fix: 'Upgrade to Solidity 0.8.x (checked math) or use SafeMath.mul with explicit bounds checks.',
        }));
      }
    }
  }

  return findings;
}

// Contract-level (not per-function) hygiene checks.
export function runContractChecks(model, source) {
  const findings = [];
  if (!model.ok) return findings;

  // Floating pragma — once per file, LOW
  if (/pragma solidity\s+\^/.test(source)) {
    const c = model.contracts[0] || { name: 'file' };
    findings.push({
      detectorId: 'SEM-floating-pragma', severity: 'LOW', baseSeverity: 'LOW',
      title: 'Floating pragma version',
      location: `${c.name}`, function: '-', contract: c.name,
      description: 'A floating ^ pragma allows compilation with future compiler versions whose behavior is unknown.',
      fix: 'Pin an exact compiler version, e.g. pragma solidity 0.8.24;',
      owasp: O.SC10.id, owaspTitle: O.SC10.title, cwe: C.CWE_665.id, cweName: C.CWE_665.name,
      mitre: M.T1195.id, mitreName: M.T1195.name,
      cvss: 2.0, cvssVector: 'AV:N/PR:H', privilegesRequired: 'high',
      userReachable: false, hasMitigation: false, confidence: 'high', source: 'semantic',
    });
  }

  return findings;
}
