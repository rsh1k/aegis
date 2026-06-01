// ─────────────────────────────────────────────────────────────────────────────
// Static detector engine — full OWASP SC Top 10 (2026) coverage
// Each detector carries: severity, OWASP id, CWE id, MITRE technique,
// confidence (regex precision), and red-team metadata (exploit likelihood +
// attacker cost). This is a heuristic layer; the Claude layer adds semantic
// findings. Heuristics WILL miss things — see DISCLAIMER.
// ─────────────────────────────────────────────────────────────────────────────

import { OWASP_SC_2026 as O, MITRE as M, CWE as C } from '../knowledge/frameworks.js';

// exploitLikelihood: how readily a remote attacker can trigger it (1-5)
// attackerCost: rough effort/capital needed (low|medium|high)
export const DETECTORS = [
  // ── SC01: Access Control ──────────────────────────────────────────────────
  {
    id: 'AC-missing-modifier',
    severity: 'CRITICAL',
    owasp: O.SC01, cwe: C.CWE_284, mitre: M.T1078,
    confidence: 'medium',
    exploitLikelihood: 5, attackerCost: 'low',
    title: 'State-changing function lacks access control',
    pattern: /function\s+(?:set|update|withdrawAll|mint|burn|upgrade|pause|unpause|grant|revoke|destroy|kill|sweep|rescue|setOwner|transferOwnership|changeOwner)\w*\s*\([^)]*\)\s*(?:external|public)(?![^{]*\b(?:onlyOwner|onlyRole|onlyAdmin|require\s*\(\s*msg\.sender|_checkRole|hasRole|auth|restricted|nonReentrant)\b)[^{]*\{/i,
    description: 'A privileged-sounding function is declared public/external with no visible access-control modifier or msg.sender check. Access-control flaws were the single largest loss category in 2024 ($953M).',
    fix: 'Apply an explicit modifier (onlyOwner / onlyRole(ROLE)) or an inline require(msg.sender == authorized). Prefer OpenZeppelin AccessControl with role separation over a single owner.',
  },
  {
    id: 'AC-tx-origin',
    severity: 'HIGH',
    owasp: O.SC01, cwe: C.CWE_285, mitre: M.T1556,
    confidence: 'high',
    exploitLikelihood: 4, attackerCost: 'low',
    title: 'tx.origin used for authorization',
    pattern: /tx\.origin\s*==|require\s*\(\s*tx\.origin/,
    description: 'tx.origin authentication is phishable: a malicious contract the victim calls will still see the victim as tx.origin, bypassing the check.',
    fix: 'Replace tx.origin with msg.sender for all authorization logic.',
  },
  {
    id: 'AC-unprotected-selfdestruct',
    severity: 'HIGH',
    owasp: O.SC01, cwe: C.CWE_284, mitre: M.T1078,
    confidence: 'high',
    exploitLikelihood: 3, attackerCost: 'medium',
    title: 'selfdestruct reachable',
    pattern: /\bselfdestruct\s*\(|\bsuicide\s*\(/,
    description: 'selfdestruct can permanently remove contract code and sweep its balance. If reachable via weak auth or delegatecall, an attacker can destroy the protocol. Deprecated under EIP-6049.',
    fix: 'Remove selfdestruct. If unavoidable, gate behind multi-sig + timelock and document the threat model.',
  },

  // ── SC10: Proxy & Upgradeability ──────────────────────────────────────────
  {
    id: 'UP-unprotected-initializer',
    severity: 'CRITICAL',
    owasp: O.SC10, cwe: C.CWE_665, mitre: M.T1078,
    confidence: 'medium',
    exploitLikelihood: 5, attackerCost: 'low',
    title: 'Initializer may be unprotected',
    pattern: /function\s+initialize\s*\([^)]*\)\s*(?:external|public)(?![^{]*\b(?:initializer|reinitializer|onlyOwner|require)\b)/,
    description: 'An initialize() function without the initializer modifier can be called by anyone, letting an attacker seize ownership of a freshly deployed proxy (classic proxy takeover).',
    fix: 'Use OpenZeppelin Initializable and the initializer modifier. Disable initializers in the implementation constructor with _disableInitializers().',
  },
  {
    id: 'UP-delegatecall',
    severity: 'HIGH',
    owasp: O.SC10, cwe: C.CWE_829, mitre: M.T1565,
    confidence: 'high',
    exploitLikelihood: 3, attackerCost: 'medium',
    title: 'delegatecall to untrusted/variable target',
    pattern: /\.delegatecall\s*\(/,
    description: 'delegatecall runs external code against this contract\'s storage. If the target is attacker-influenced or upgradeable, storage can be corrupted or control seized.',
    fix: 'Restrict delegatecall to immutable, audited implementation addresses. Use a vetted proxy pattern (UUPS/Transparent) with storage-gap discipline.',
  },

  // ── SC03: Price Oracle Manipulation ───────────────────────────────────────
  {
    id: 'OR-spot-price',
    severity: 'HIGH',
    owasp: O.SC03, cwe: C.CWE_345, mitre: M.T1565,
    confidence: 'medium',
    exploitLikelihood: 4, attackerCost: 'medium',
    title: 'Spot price used as oracle (manipulable)',
    pattern: /getReserves\s*\(\)|\.price0CumulativeLast|\.price1CumulativeLast|balanceOf\s*\([^)]*\)\s*[*/]\s*|\.getAmountsOut\s*\(/,
    description: 'Reading instantaneous DEX reserves/spot price as a trusted value is manipulable within a single block via flash loans, enabling mispriced borrows and liquidations.',
    fix: 'Use a manipulation-resistant oracle: Chainlink price feeds, or a TWAP with sufficient window. Never use single-block spot price for valuation.',
  },

  // ── SC04: Flash Loan-Facilitated ──────────────────────────────────────────
  {
    id: 'FL-flashloan-callback',
    severity: 'MEDIUM',
    owasp: O.SC04, cwe: C.CWE_841, mitre: M.T1565,
    confidence: 'low',
    exploitLikelihood: 3, attackerCost: 'low',
    title: 'Flash loan callback present — verify invariants',
    pattern: /function\s+(?:executeOperation|onFlashLoan|receiveFlashLoan|uniswapV[23]Call|pancakeCall)\s*\(/,
    description: 'A flash-loan callback is implemented. These are legitimate, but they are the entry point most often abused to chain price manipulation + logic bugs into single-tx drains. Confirm all economic invariants hold mid-callback.',
    fix: 'Validate caller, enforce post-state invariants, and avoid trusting in-transaction prices. Add reentrancy protection around callback-affected state.',
  },

  // ── SC08: Reentrancy ──────────────────────────────────────────────────────
  {
    id: 'RE-external-before-state',
    severity: 'CRITICAL',
    owasp: O.SC08, cwe: C.CWE_841b, mitre: M.T1565,
    confidence: 'medium',
    exploitLikelihood: 4, attackerCost: 'low',
    title: 'External call before state update (reentrancy)',
    pattern: /(?:\.call\{\s*value\s*:[^}]*\}\([^)]*\)|\.call\.value\s*\([^)]*\)\s*\([^)]*\))[\s\S]{0,240}?(?:balances?|credit|shares?|deposits?)\s*\[[^\]]+\]\s*(?:-=|=)/,
    description: 'Value-bearing external call appears before the corresponding balance update. A malicious recipient can re-enter and withdraw repeatedly (the DAO-class bug).',
    fix: 'Apply Checks-Effects-Interactions: update state before the external call. Add OpenZeppelin ReentrancyGuard (nonReentrant).',
  },
  {
    id: 'RE-no-guard',
    severity: 'LOW',
    owasp: O.SC08, cwe: C.CWE_362, mitre: M.T1565,
    confidence: 'low',
    exploitLikelihood: 2, attackerCost: 'low',
    title: 'Value transfers without ReentrancyGuard',
    pattern: /\.call\{\s*value/,
    requiresAbsence: /ReentrancyGuard|nonReentrant/,
    description: 'Contract makes value-bearing calls but imports no reentrancy guard. Even with CEI, defense-in-depth is recommended.',
    fix: 'Add OpenZeppelin ReentrancyGuard and apply nonReentrant to all functions making external value calls.',
  },

  // ── SC06: Unchecked External Calls ────────────────────────────────────────
  {
    id: 'EC-unchecked-call',
    severity: 'HIGH',
    owasp: O.SC06, cwe: C.CWE_252, mitre: M.T1565,
    confidence: 'medium',
    exploitLikelihood: 3, attackerCost: 'low',
    title: 'Unchecked low-level call return value',
    pattern: /[^\S\n]*[\w.]+\.call(?:\{[^}]{0,80}\}|\.value\([^)]{0,40}\))?\([^)]{0,80}\)[^\S\n]*;/,
    requiresAbsence: /\(\s*bool\s+\w+\s*,/,
    description: 'A low-level .call return value is not captured/checked. Silent failure lets execution continue under a false success assumption.',
    fix: '(bool ok, ) = target.call{...}(...); require(ok, "call failed"); Prefer typed interfaces over raw call where possible.',
  },
  {
    id: 'EC-erc20-no-safe',
    severity: 'MEDIUM',
    owasp: O.SC06, cwe: C.CWE_252, mitre: M.T1565,
    confidence: 'medium',
    exploitLikelihood: 2, attackerCost: 'low',
    title: 'ERC20 transfer/transferFrom return not checked',
    pattern: /(?<!Safe(?:ERC20)?\.)\b\w*\.(?:transfer|transferFrom)\s*\([^)]*\)\s*;/,
    description: 'Some tokens (e.g. USDT) return false instead of reverting. Unchecked transfers silently fail, desyncing accounting.',
    fix: 'Use OpenZeppelin SafeERC20 (safeTransfer / safeTransferFrom).',
  },

  // ── SC05: Lack of Input Validation ────────────────────────────────────────
  {
    id: 'IV-no-zero-address',
    severity: 'MEDIUM',
    owasp: O.SC05, cwe: C.CWE_20, mitre: M.T1190,
    confidence: 'low',
    exploitLikelihood: 2, attackerCost: 'low',
    title: 'Address parameter without zero-address check',
    pattern: /function\s+\w+\s*\([^)]*address\s+\w+[^)]*\)\s*(?:external|public)(?![^{]*require\s*\([^)]*!=\s*address\(0\))/,
    description: 'A function takes an address argument with no visible zero-address validation. Setting critical addresses to 0x0 can brick the contract or burn funds.',
    fix: 'require(addr != address(0), "zero address") for all externally supplied addresses used in state or transfers.',
  },

  // ── SC07 / SC09: Arithmetic / Overflow ────────────────────────────────────
  {
    id: 'AR-old-solidity',
    severity: 'HIGH',
    owasp: O.SC09, cwe: C.CWE_190, mitre: M.T1565,
    confidence: 'high',
    exploitLikelihood: 3, attackerCost: 'low',
    title: 'Solidity < 0.8.0 without overflow protection',
    pattern: /pragma solidity\s+[^;]*0\.[0-7]\./,
    requiresAbsence: /SafeMath/,
    description: 'Pre-0.8 Solidity has no built-in overflow/underflow checks and no SafeMath import detected. Arithmetic can silently wrap.',
    fix: 'Upgrade to Solidity ^0.8.x, or import and use OpenZeppelin SafeMath consistently.',
  },
  {
    id: 'AR-unguarded-multiply',
    severity: 'CRITICAL',
    owasp: O.SC09, cwe: C.CWE_190, mitre: M.T1565,
    confidence: 'medium',
    exploitLikelihood: 4, attackerCost: 'low',
    title: 'Unguarded multiplication in pre-0.8 Solidity (overflow)',
    // matches `... = a * b` style assignments on old compilers (incl. casts)
    pattern: /(?:uint\d*\s+\w+\s*=|\breturn\b)[^;=]{0,60}[\w)]\s*\*\s*\w+/,
    requiresAbsence: /SafeMath|pragma solidity\s+[\^>=~ ]*0\.(?:8|9)\.|pragma solidity\s+[\^>=~ ]*[1-9]\d*\.\d/,
    description: 'A multiplication assigns into a fixed-width integer on a pre-0.8 compiler with no SafeMath. A large multiplier overflows and wraps to a small value — exactly the BeautyChain (BEC) batchTransfer overflow that let an attacker mint astronomical balances in 2018.',
    fix: 'Upgrade to Solidity 0.8.x (checked arithmetic) or wrap every multiplication in SafeMath.mul(). Validate that amount = count * value cannot exceed the sender balance before mutating state.',
  },
  {
    id: 'AR-unchecked-block',
    severity: 'MEDIUM',
    owasp: O.SC07, cwe: C.CWE_682, mitre: M.T1565,
    confidence: 'medium',
    exploitLikelihood: 2, attackerCost: 'medium',
    title: 'unchecked{} arithmetic block',
    pattern: /\bunchecked\s*\{/,
    description: 'unchecked{} disables overflow protection for performance. Legitimate, but each block must be proven safe — a wrong assumption reintroduces overflow bugs.',
    fix: 'Confirm every operation in unchecked blocks cannot overflow for all reachable inputs. Document the invariant inline.',
  },

  // ── SC02: Business Logic (heuristic flags only) ───────────────────────────
  {
    id: 'BL-divide-before-multiply',
    severity: 'MEDIUM',
    owasp: O.SC02, cwe: C.CWE_682, mitre: M.T1565,
    confidence: 'low',
    exploitLikelihood: 2, attackerCost: 'medium',
    title: 'Division before multiplication (precision loss)',
    pattern: /\/\s*\w+\s*\*\s*\w+/,
    description: 'Dividing before multiplying truncates intermediate results, causing precision loss exploitable in share/interest math, especially when amplified by flash loans.',
    fix: 'Reorder to multiply before dividing, or use a fixed-point math library (PRBMath, ABDKMath).',
  },

  // ── Randomness / Timestamp (logic class) ──────────────────────────────────
  {
    id: 'Rand-weak-randomness',
    severity: 'HIGH',
    owasp: O.SC02, cwe: C.CWE_330, mitre: M.T1565,
    confidence: 'medium',
    exploitLikelihood: 4, attackerCost: 'low',
    title: 'Insecure on-chain randomness',
    pattern: /keccak256\s*\([^)]*(?:block\.(?:timestamp|number|difficulty|prevrandao)|blockhash)[^)]*\)/,
    description: 'Deriving randomness from block properties is predictable/influenceable by validators, breaking lotteries, mints, and games.',
    fix: 'Use a verifiable randomness source (Chainlink VRF) for any value an attacker would profit from predicting.',
  },
  {
    id: 'TS-timestamp-logic',
    severity: 'LOW',
    owasp: O.SC02, cwe: C.CWE_682, mitre: M.T1565,
    confidence: 'medium',
    exploitLikelihood: 2, attackerCost: 'medium',
    title: 'block.timestamp used in comparison logic',
    pattern: /block\.timestamp\s*[<>]=?|[<>]=?\s*block\.timestamp/,
    description: 'Validators can nudge block.timestamp by a few seconds. Avoid using it for tight deadlines or randomness.',
    fix: 'Allow tolerance, or use block.number for relative timing where precision matters.',
  },

  // ── DoS (resource exhaustion) ─────────────────────────────────────────────
  {
    id: 'DoS-unbounded-loop',
    severity: 'MEDIUM',
    owasp: O.SC02, cwe: C.CWE_400, mitre: M.T1499,
    confidence: 'low',
    exploitLikelihood: 3, attackerCost: 'low',
    title: 'Unbounded loop over dynamic array',
    pattern: /for\s*\([^;]*;\s*\w+\s*<\s*\w+\.length\s*;/,
    description: 'Looping over an array that an attacker can grow can push gas past the block limit, permanently bricking the function (griefing DoS).',
    fix: 'Bound iterations, use pull-over-push patterns, or paginate. Never iterate attacker-controllable unbounded arrays in a single tx.',
  },

  // ── Hygiene / supply-chain ────────────────────────────────────────────────
  {
    id: 'HY-floating-pragma',
    severity: 'LOW',
    owasp: O.SC10, cwe: C.CWE_665, mitre: M.T1195,
    confidence: 'high',
    exploitLikelihood: 1, attackerCost: 'high',
    title: 'Floating pragma version',
    pattern: /pragma solidity\s+\^/,
    description: 'A floating ^ pragma allows compilation with future compiler versions whose behavior/bugs are unknown — a small supply-chain risk.',
    fix: 'Pin an exact, audited compiler version, e.g. pragma solidity 0.8.24;',
  },
];

// Run all detectors against source. Returns normalized findings with framework tags.
export function runDetectors(source) {
  const findings = [];
  const lines = source.split('\n');

  for (const d of DETECTORS) {
    // Skip detectors whose "absence" precondition is violated
    if (d.requiresAbsence && d.requiresAbsence.test(source)) continue;

    if (d.pattern.test(source)) {
      let lineNum = null;
      for (let i = 0; i < lines.length; i++) {
        // Reset lastIndex for global-less regex safety
        if (new RegExp(d.pattern.source, d.pattern.flags.replace('g', '')).test(lines[i])) {
          lineNum = i + 1;
          break;
        }
      }
      findings.push({
        detectorId:  d.id,
        severity:    d.severity,
        title:       d.title,
        location:    lineNum ? `Line ${lineNum}` : 'Multiple locations',
        description: d.description,
        fix:         d.fix,
        owasp:       d.owasp.id,
        owaspTitle:  d.owasp.title,
        cwe:         d.cwe.id,
        cweName:     d.cwe.name,
        mitre:       d.mitre.id,
        mitreName:   d.mitre.name,
        confidence:  d.confidence,
        exploitLikelihood: d.exploitLikelihood,
        attackerCost:      d.attackerCost,
        source:      'static',
      });
    }
  }

  return findings;
}

export function gatherMetrics(source) {
  const lines = source.split('\n');
  return {
    lines: lines.length,
    contracts:  (source.match(/\bcontract\s+\w+/g) || []).length,
    functions:  (source.match(/\bfunction\s+\w+/g) || []).length,
    modifiers:  (source.match(/\bmodifier\s+\w+/g) || []).length,
    externalFunctions: (source.match(/\b(?:external|public)\s+/g) || []).length,
    hasOwnable:          /Ownable|onlyOwner/.test(source),
    hasAccessControl:    /AccessControl|onlyRole|hasRole/.test(source),
    hasReentrancyGuard:  /ReentrancyGuard|nonReentrant/.test(source),
    hasSafeMath:         /SafeMath|using SafeMath/.test(source),
    hasSafeERC20:        /SafeERC20/.test(source),
    usesOracle:          /Chainlink|AggregatorV3|getReserves|oracle/i.test(source),
    isUpgradeable:       /Initializable|UUPS|delegatecall|Proxy/i.test(source),
    hasEvents:           /emit\s+\w+/.test(source),
    solidityVersion:     (source.match(/pragma solidity\s+([^;]+);/) || [])[1]?.trim() || 'unknown',
  };
}
