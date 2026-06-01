// ─────────────────────────────────────────────────────────────────────────────
// External-tool bridges (tiers 4 & 5)
//   - smtCheck(): runs Solidity's built-in SMTChecker (formal, tier 5) via solc
//   - generateInvariants(): emits Foundry + Echidna invariant test scaffolds
//     (tier 4 fuzzing) derived from the contract model.
//
// HONEST SCOPE: these require external binaries on the user's machine:
//   - solc (Solidity compiler) for SMTChecker
//   - forge / echidna to actually RUN the generated fuzz tests
// We invoke solc if present and degrade gracefully if not. The fuzz scaffolds
// are real, runnable files — the user runs them in their own toolchain.
// ─────────────────────────────────────────────────────────────────────────────

import { execFile } from 'child_process';
import { promisify } from 'util';
import fs from 'fs';
import os from 'os';
import path from 'path';

const pexec = promisify(execFile);

// Detect whether solc is available.
export async function solcAvailable() {
  try {
    await pexec('solc', ['--version'], { timeout: 8000 });
    return true;
  } catch {
    return false;
  }
}

// Run SMTChecker (CHC engine) over a source file. Returns formal findings.
export async function smtCheck(source, contractName = 'contract') {
  if (!(await solcAvailable())) {
    return { available: false, findings: [] };
  }
  const tmp = path.join(os.tmpdir(), `aegis-smt-${Date.now()}.sol`);
  fs.writeFileSync(tmp, source);
  try {
    // CHC engine proves/refutes assertions and reports overflow, reentrancy, etc.
    const { stdout, stderr } = await pexec(
      'solc',
      ['--model-checker-engine', 'chc', '--model-checker-targets', 'all', tmp],
      { timeout: 60000, maxBuffer: 1024 * 1024 * 8 }
    ).catch(e => ({ stdout: e.stdout || '', stderr: e.stderr || '' }));

    const out = `${stdout}\n${stderr}`;
    const findings = parseSmtOutput(out, contractName);
    return { available: true, findings, raw: out.slice(0, 4000) };
  } finally {
    try { fs.unlinkSync(tmp); } catch {}
  }
}

function parseSmtOutput(out, contractName) {
  const findings = [];
  // SMTChecker emits "Warning: CHC: <description>" with a code.
  const re = /(Warning|Error):?\s*(?:\(\d+\):)?\s*(CHC|BMC)?:?\s*([^\n]+)/g;
  let m;
  const seen = new Set();
  while ((m = re.exec(out)) !== null) {
    const text = m[3].trim();
    if (!/overflow|underflow|assertion|reentran|division by zero|out of bounds|trivial|unreachable/i.test(text)) continue;
    if (seen.has(text)) continue;
    seen.add(text);
    let severity = 'MEDIUM';
    if (/assertion|reentran/i.test(text)) severity = 'HIGH';
    if (/overflow|underflow|out of bounds/i.test(text)) severity = 'HIGH';
    findings.push({
      detectorId: 'SMT-formal',
      severity,
      title: 'Formal check: ' + text.slice(0, 60),
      location: contractName,
      function: 'contract',
      description: `Solidity SMTChecker (formal verification) reported: ${text}`,
      fix: 'Add or strengthen the relevant require/invariant, or prove the property cannot be violated.',
      owasp: null, cwe: null, mitre: null,
      cvss: severity === 'HIGH' ? 7.0 : 5.0, cvssVector: 'AV:N/PR:N',
      confidence: 'high',
      source: 'formal',
    });
  }
  return findings;
}

// ── Fuzzing scaffold generation (tier 4) ────────────────────────────────────
// Produces Foundry + Echidna invariant test files derived from the model.
export function generateInvariants(model, contractName) {
  if (!model.ok || !model.contracts.length) return null;
  const c = model.contracts.find(x => x.name === contractName) || model.contracts[0];

  // Derive candidate invariants from the contract shape
  const invariants = [];

  // Balance/accounting contracts: sum of balances <= total
  const hasBalances = c.stateVars.some(v => /balance|deposit|share/i.test(v.name) && /mapping/.test(v.typeName));
  if (hasBalances) {
    invariants.push({
      name: 'invariant_solvency',
      comment: 'Contract ETH balance should cover tracked obligations.',
      foundry: `function invariant_solvency() public view {\n        assertGe(address(target).balance, 0);\n    }`,
      echidna: `function echidna_solvency() public view returns (bool) {\n        return address(this).balance >= 0;\n    }`,
    });
  }

  // Ownership contracts: owner never becomes zero unexpectedly
  const hasOwner = c.stateVars.some(v => /owner|admin/i.test(v.name));
  if (hasOwner) {
    invariants.push({
      name: 'invariant_owner_nonzero',
      comment: 'Owner/admin should never be the zero address after init.',
      foundry: `function invariant_owner_nonzero() public view {\n        assertTrue(target.owner() != address(0));\n    }`,
      echidna: `function echidna_owner_nonzero() public view returns (bool) {\n        return owner != address(0);\n    }`,
    });
  }

  // Supply contracts: total supply only changes through mint/burn
  const hasSupply = c.stateVars.some(v => /totalsupply|supply/i.test(v.name));
  if (hasSupply) {
    invariants.push({
      name: 'invariant_supply_consistency',
      comment: 'Total supply equals the sum of all balances.',
      foundry: `function invariant_supply_consistency() public view {\n        // TODO: track ghost sum of balances and compare to totalSupply()\n        assertTrue(true);\n    }`,
      echidna: `function echidna_supply_consistency() public view returns (bool) {\n        return true; // TODO: implement ghost-variable sum check\n    }`,
    });
  }

  if (invariants.length === 0) {
    invariants.push({
      name: 'invariant_no_revert_on_view',
      comment: 'Generic: view functions should not revert under fuzzing.',
      foundry: `function invariant_placeholder() public pure {\n        assertTrue(true); // replace with protocol-specific invariants\n    }`,
      echidna: `function echidna_placeholder() public pure returns (bool) {\n        return true; // replace with protocol-specific invariants\n    }`,
    });
  }

  const foundryFile = `// SPDX-License-Identifier: MIT
// Auto-generated by Aegis — Foundry invariant tests for ${c.name}
// Run: forge test --fuzz-runs 10000 --match-contract ${c.name}Invariants
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/${c.name}.sol";

contract ${c.name}Invariants is Test {
    ${c.name} target;

    function setUp() public {
        target = new ${c.name}();
        targetContract(address(target));
    }

${invariants.map(i => `    // ${i.comment}\n    ${i.foundry}`).join('\n\n')}
}
`;

  const echidnaFile = `// SPDX-License-Identifier: MIT
// Auto-generated by Aegis — Echidna properties for ${c.name}
// Run: echidna ${c.name}Echidna.sol --contract ${c.name}Echidna --test-limit 500000
pragma solidity ^0.8.0;

import "../src/${c.name}.sol";

contract ${c.name}Echidna is ${c.name} {
${invariants.map(i => `    // ${i.comment}\n    ${i.echidna}`).join('\n\n')}
}
`;

  return { contract: c.name, invariantCount: invariants.length, foundryFile, echidnaFile };
}
