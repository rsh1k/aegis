// ─────────────────────────────────────────────────────────────────────────────
// Cross-function taint analysis (tier-2 static analysis)
// Builds a call graph across functions and propagates "taint" (attacker-control)
// from SOURCES to SINKS. A finding fires only when a tainted value reaches a
// dangerous sink WITHOUT passing a guard/sanitizer — this is what separates
// real dataflow analysis from per-line pattern matching, and it is the main
// lever for cutting false positives while raising recall on multi-function bugs.
//
// Model (intentionally conservative — we under-claim rather than over-flag):
//   SOURCES (tainted):   function parameters of external/public fns, msg.data,
//                        return values of external calls, block.* values.
//   SANITIZERS:          require()/assert() that constrains the value, access
//                        guards (onlyOwner etc.), explicit bound checks.
//   SINKS:               external call targets/values, delegatecall targets,
//                        array index writes, arithmetic into state, selfdestruct
//                        argument, storage writes used in auth decisions.
//
// Cross-function: if fn A passes a tainted arg into internal fn B, B's matching
// parameter becomes tainted. We iterate to a fixpoint over the call graph.
// ─────────────────────────────────────────────────────────────────────────────

import { OWASP_SC_2026 as O, MITRE as M, CWE as C } from '../knowledge/frameworks.js';

// Build: map of fnName -> { params, callsWithArgs:[{callee,args}], sinks:[...],
//                          sanitizesParams:Set, taintedLocals:Set }
// then propagate.
export function analyzeTaint(model) {
  const findings = [];
  if (!model.ok) return findings;

  for (const contract of model.contracts) {
    if (contract.kind === 'interface') continue;
    const fnIndex = new Map(contract.functions.map(f => [f.name, f]));

    // 1. Seed taint: external/public params are attacker-controlled.
    // We track taint at the granularity of parameter/local NAMES per function.
    const taintState = new Map(); // fnName -> Set(taintedVarNames)
    for (const fn of contract.functions) {
      const seed = new Set();
      const externallyReachable = ['public', 'external', 'default'].includes(fn.visibility);
      if (externallyReachable && !fn.hasAccessControl) {
        for (const p of fn.params) if (p.name) seed.add(p.name);
      }
      taintState.set(fn.name, seed);
    }

    // 2. Fixpoint propagation across internal calls.
    // If fn A calls B(arg) and arg is tainted in A, then B's matching param is tainted.
    let changed = true, iterations = 0;
    while (changed && iterations < 12) {
      changed = false; iterations++;
      for (const fn of contract.functions) {
        const myTaint = taintState.get(fn.name);
        for (const call of (fn.taintEdges || [])) {
          const callee = fnIndex.get(call.callee);
          if (!callee) continue;
          const calleeTaint = taintState.get(callee.name);
          call.args.forEach((argName, i) => {
            const param = callee.params[i];
            if (!param || !param.name) return;
            // Tainted if the passed arg is a tainted var in the caller
            if (myTaint.has(argName) && !calleeTaint.has(param.name)) {
              calleeTaint.add(param.name);
              changed = true;
            }
          });
        }
      }
    }

    // 3. Check sinks against taint + sanitization.
    for (const fn of contract.functions) {
      const tainted = taintState.get(fn.name);
      if (tainted.size === 0) continue;

      for (const sink of (fn.taintSinks || [])) {
        // Is any operand of this sink tainted and NOT sanitized in this fn?
        const taintedOperand = sink.operands.find(op => tainted.has(op) && !fn.sanitizedVars?.has(op));
        if (!taintedOperand) continue;

        const def = SINK_DEFS[sink.kind];
        if (!def) continue;

        findings.push({
          detectorId: `TAINT-${sink.kind}`,
          severity: def.severity,
          baseSeverity: def.severity,
          title: def.title,
          location: `${contract.name}.${fn.name}${sink.line ? ` (line ${sink.line})` : ''}`,
          function: fn.name,
          contract: contract.name,
          description: `${def.desc} The value '${taintedOperand}' is attacker-controllable (reaches this sink from an unguarded external entry point) and is not constrained by a require/guard before use.`,
          fix: def.fix,
          owasp: def.owasp.id, owaspTitle: def.owasp.title,
          cwe: def.cwe.id, cweName: def.cwe.name,
          mitre: def.mitre.id, mitreName: def.mitre.name,
          cvss: def.cvss, cvssVector: 'AV:N/PR:N',
          privilegesRequired: 'none', userReachable: true, hasMitigation: false,
          confidence: 'medium',
          source: 'taint',
          taintPath: `external input → ${fn.name}.${taintedOperand} → ${sink.kind}`,
        });
      }
    }
  }

  return dedupeTaint(findings);
}

const SINK_DEFS = {
  'delegatecall-target': {
    severity: 'CRITICAL', owasp: O.SC10, cwe: C.CWE_829, mitre: M.T1565, cvss: 9.3,
    title: 'Attacker-controlled delegatecall target',
    desc: 'A delegatecall executes code at an address derived from external input.',
    fix: 'Never derive a delegatecall target from user input. Use an immutable, audited implementation address.',
  },
  'call-target': {
    severity: 'HIGH', owasp: O.SC06, cwe: C.CWE_829, mitre: M.T1565, cvss: 7.5,
    title: 'Attacker-controlled external call target',
    desc: 'The destination of an external call is derived from external input.',
    fix: 'Validate the target against an allowlist, or restrict who can set it.',
  },
  'index-write': {
    severity: 'HIGH', owasp: O.SC05, cwe: C.CWE_20, mitre: M.T1565, cvss: 7.0,
    title: 'Unvalidated index/key from external input',
    desc: 'An attacker-controlled value is used to index a storage write.',
    fix: 'Bound-check the index/key with require() before the write.',
  },
  'selfdestruct-arg': {
    severity: 'CRITICAL', owasp: O.SC01, cwe: C.CWE_284, mitre: M.T1078, cvss: 9.0,
    title: 'Attacker-controlled selfdestruct beneficiary',
    desc: 'The recipient of a selfdestruct is derived from external input.',
    fix: 'Remove selfdestruct, or fix the beneficiary and gate behind multi-sig.',
  },
  'unchecked-arithmetic': {
    severity: 'MEDIUM', owasp: O.SC07, cwe: C.CWE_682, mitre: M.T1565, cvss: 5.0,
    title: 'Attacker-controlled value in unchecked arithmetic',
    desc: 'External input flows into arithmetic that may overflow or distort accounting.',
    fix: 'Validate ranges with require() and use checked math (Solidity 0.8+).',
  },
};

function dedupeTaint(findings) {
  const seen = new Set();
  return findings.filter(f => {
    const k = `${f.detectorId}::${f.location}`;
    if (seen.has(k)) return false;
    seen.add(k); return true;
  });
}
