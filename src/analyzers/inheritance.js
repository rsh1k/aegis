// ─────────────────────────────────────────────────────────────────────────────
// Inheritance resolution
// Real projects span base + derived contracts. A guard like onlyOwner is usually
// defined in a base (Ownable) and used in the derived contract. Without resolving
// inheritance, the analyzer either misses that the modifier IS a guard, or flags
// access-control bugs that are actually handled in a parent.
//
// This flattens, per contract: inherited modifier definitions and inherited
// state vars, so the semantic + taint layers see the full picture.
//
// Limitation (stated honestly): single-file resolution only. Cross-FILE imports
// (import "./Ownable.sol") need the imported source to be present in the same
// parse. When sources are concatenated (the common flattened-contract case, and
// how Etherscan returns multi-file verified source), this works. For separate
// files, run on the flattened build output.
// ─────────────────────────────────────────────────────────────────────────────

// Well-known base contracts whose modifiers are guards even if their body
// isn't in scope (e.g. OpenZeppelin imported but not inlined).
const KNOWN_GUARD_BASES = {
  Ownable:        { modifiers: { onlyOwner: { hasSenderCheck: true } } },
  Ownable2Step:   { modifiers: { onlyOwner: { hasSenderCheck: true } } },
  AccessControl:  { modifiers: { onlyRole: { hasSenderCheck: true } } },
  AccessControlEnumerable: { modifiers: { onlyRole: { hasSenderCheck: true } } },
  ReentrancyGuard:{ modifiers: { nonReentrant: { hasReentrancyLock: true } } },
  Pausable:       { modifiers: { whenNotPaused: {}, whenPaused: {} } },
};

export function resolveInheritance(model) {
  if (!model.ok) return model;

  const byName = new Map(model.contracts.map(c => [c.name, c]));

  for (const contract of model.contracts) {
    const inheritedModifiers = {};
    const inheritedStateVars = [];
    const visited = new Set();

    const collect = (baseName) => {
      if (visited.has(baseName)) return;
      visited.add(baseName);

      // Known library base (OZ etc.) — inject its guard modifiers
      if (KNOWN_GUARD_BASES[baseName]) {
        Object.assign(inheritedModifiers, KNOWN_GUARD_BASES[baseName].modifiers);
      }

      // Local base contract present in the same parse
      const base = byName.get(baseName);
      if (base) {
        Object.assign(inheritedModifiers, base.modifiers);
        inheritedStateVars.push(...base.stateVars);
        for (const grand of base.baseContracts) collect(grand);
      }
    };

    for (const b of contract.baseContracts) collect(b);

    // Merge inherited modifiers (own definitions win on conflict)
    contract.modifiers = { ...inheritedModifiers, ...contract.modifiers };
    contract.inheritedStateVars = inheritedStateVars;
    contract.resolvedBases = [...visited];

    // Re-resolve guards on each function now that inherited modifiers are known
    for (const fn of contract.functions) {
      for (const m of fn.modifiers) {
        const md = contract.modifiers[m];
        if (md?.hasSenderCheck) fn.hasAccessControl = true;
        if (md?.hasReentrancyLock) fn.hasReentrancyGuard = true;
        // name-based fallback for known guard modifiers
        if (/^(onlyOwner|onlyRole|onlyAdmin|onlyGovernance|whenNotPaused)$/i.test(m)) fn.hasAccessControl = true;
        if (/^(nonReentrant|noReentrancy)$/i.test(m)) fn.hasReentrancyGuard = true;
      }
    }
  }

  return model;
}
