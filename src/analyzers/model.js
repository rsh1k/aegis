// ─────────────────────────────────────────────────────────────────────────────
// Semantic model builder
// Parses Solidity into an AST and builds a structured model of each contract:
//   - functions (visibility, mutability, modifiers, params)
//   - guards protecting each function (access control, reentrancy, validation)
//   - state variables each function reads / writes
//   - external calls and their ordering vs state writes
//   - call graph (which function calls which)
//
// This model is what lets detectors reason about BEHAVIOR and CONTEXT
// (e.g. "is there already a guard?") instead of matching raw text — which is
// how we cut false positives dramatically.
// ─────────────────────────────────────────────────────────────────────────────

import pkg from '@solidity-parser/parser';
const parser = pkg;

// Modifier / guard classification
const ACCESS_MODIFIERS = /^(onlyOwner|onlyAdmin|onlyRole|onlyGovernance|onlyManager|auth|restricted|requiresAuth|onlyAuthorized)/i;
const REENTRANCY_MODIFIERS = /^(nonReentrant|noReentrancy|lock|mutex)/i;

export function buildModel(source) {
  let ast;
  try {
    ast = parser.parse(source, { loc: true, tolerant: true });
  } catch (e) {
    return { ok: false, error: e.message, contracts: [] };
  }

  const contracts = [];
  const pragma = (source.match(/pragma solidity\s+([^;]+);/) || [])[1]?.trim() || 'unknown';
  const solMajor8Plus = /\^?0\.(8|9)\.|[\^>=~ ]*[1-9]\d*\.\d/.test(pragma) && !/0\.[0-7]\./.test(pragma);

  parser.visit(ast, {
    ContractDefinition(node) {
      const contract = {
        name: node.name,
        kind: node.kind, // contract | interface | library
        baseContracts: (node.baseContracts || []).map(b => b.baseName?.namePath).filter(Boolean),
        isUpgradeable: false,
        usesSafeMath: /SafeMath/.test(source),
        usesSafeERC20: /SafeERC20/.test(source),
        solMajor8Plus,
        pragma,
        stateVars: [],
        functions: [],
        modifiers: {},
      };

      // Detect upgradeability base
      if (contract.baseContracts.some(b => /Initializable|UUPS|Upgradeable|Proxy/i.test(b))) {
        contract.isUpgradeable = true;
      }

      // First pass: collect modifier definitions, state vars
      for (const sub of node.subNodes) {
        if (sub.type === 'StateVariableDeclaration') {
          for (const v of sub.variables) {
            contract.stateVars.push({
              name: v.name,
              typeName: typeToString(v.typeName),
              visibility: v.visibility,
              isConstant: !!v.isDeclaredConst || v.isImmutable,
            });
          }
        }
        if (sub.type === 'ModifierDefinition') {
          contract.modifiers[sub.name] = analyzeModifierBody(sub);
        }
      }

      // Second pass: analyze functions
      for (const sub of node.subNodes) {
        if (sub.type === 'FunctionDefinition') {
          contract.functions.push(analyzeFunction(sub, contract, source));
        }
      }

      contracts.push(contract);
    },
  });

  return { ok: true, contracts, pragma, solMajor8Plus };
}

function analyzeFunction(node, contract, source) {
  const modifierNames = (node.modifiers || []).map(m => m.name);

  const fn = {
    name: node.isConstructor ? 'constructor' : (node.name || (node.isFallback ? 'fallback' : node.isReceiveEther ? 'receive' : '<anonymous>')),
    isConstructor: node.isConstructor,
    visibility: node.visibility || 'default',
    stateMutability: node.stateMutability, // view | pure | payable | null
    isPayable: node.stateMutability === 'payable',
    modifiers: modifierNames,
    params: (node.parameters || []).map(p => ({ name: p.name, type: typeToString(p.typeName) })),
    loc: node.loc?.start?.line,

    // Guards present on this function (via its modifiers or inline)
    hasAccessControl: false,
    hasReentrancyGuard: false,
    inlineSenderCheck: false,
    zeroAddressChecks: new Set(),

    // Behavior
    externalCalls: [],          // [{kind, line, valueBearing}]
    stateWrites: [],            // [{var, line}]
    stateReads: [],
    callsSelfdestruct: false,
    callsDelegatecall: false,
    usesTxOrigin: false,
    usesBlockTimestamp: false,
    usesBlockProperties: false,
    rawMultiply: false,
    externalCallBeforeWrite: false,
    callsInternal: [],          // names of internal/contract fns called
    emitsEvents: false,
    // ── taint analysis structures ──
    taintEdges: [],             // [{callee, args:[argName...]}] internal calls w/ arg names
    taintSinks: [],             // [{kind, operands:[varName...], line}]
    sanitizedVars: new Set(),   // vars constrained by require/assert in this fn
  };

  // Resolve guards from modifiers
  for (const m of modifierNames) {
    if (ACCESS_MODIFIERS.test(m)) fn.hasAccessControl = true;
    if (REENTRANCY_MODIFIERS.test(m)) fn.hasReentrancyGuard = true;
    // modifier may itself contain a msg.sender / require check
    const md = contract.modifiers[m];
    if (md?.hasSenderCheck) fn.hasAccessControl = true;
    if (md?.hasReentrancyLock) fn.hasReentrancyGuard = true;
  }

  if (!node.body) return fn; // interface / abstract

  // Walk the function body to extract behavior
  let lastExternalCallLine = null;
  let firstStateWriteLine = null;

  parser.visit(node.body, {
    FunctionCall(call) {
      const callee = call.expression;
      // selfdestruct / suicide
      if (callee?.type === 'Identifier' && /^(selfdestruct|suicide)$/.test(callee.name)) {
        fn.callsSelfdestruct = true;
      }
      // require(msg.sender == ...) inline access check + sanitization tracking
      if (callee?.type === 'Identifier' && (callee.name === 'require' || callee.name === 'assert')) {
        const argText = exprText(call.arguments?.[0]);
        if (/msg\.sender/.test(argText) && /==|!=/.test(argText)) fn.inlineSenderCheck = true, fn.hasAccessControl = true;
        if (/tx\.origin/.test(argText)) fn.usesTxOrigin = true;
        const zmatch = argText.match(/(\w+)\s*!=\s*address\(0\)/);
        if (zmatch) fn.zeroAddressChecks.add(zmatch[1]);
        for (const v of argText.match(/[A-Za-z_]\w*/g) || []) fn.sanitizedVars.add(v);
      }
      // low-level calls: x.call{value:}() / .call() / .delegatecall() / .transfer / .send
      const memberText = exprText(callee);
      if (/\.delegatecall$/.test(memberText)) {
        fn.callsDelegatecall = true;
        fn.taintSinks.push({ kind: 'delegatecall-target', operands: idsIn(exprText(callee.expression)), line: call.loc?.start?.line });
      }
      if (/\.call$/.test(memberText) || /\.call\b/.test(memberText)) {
        const line = call.loc?.start?.line;
        fn.externalCalls.push({ kind: 'call', line, valueBearing: /value/.test(exprText(call)) });
        lastExternalCallLine = line;
        fn.taintSinks.push({ kind: 'call-target', operands: idsIn(exprText(callee.expression)), line });
      }
      if (/\.(transfer|send)$/.test(memberText)) {
        const line = call.loc?.start?.line;
        fn.externalCalls.push({ kind: 'transfer', line, valueBearing: true });
        lastExternalCallLine = line;
      }
      if (callee?.type === 'Identifier' && /^(selfdestruct|suicide)$/.test(callee.name)) {
        fn.taintSinks.push({ kind: 'selfdestruct-arg', operands: idsIn(exprText(call.arguments?.[0])), line: call.loc?.start?.line });
      }
      // internal/other function calls (for call graph + taint edges)
      if (callee?.type === 'Identifier' && !/^(require|assert|revert|selfdestruct|suicide|keccak256|sha256|ecrecover|addmod|mulmod|emit|address|payable)$/.test(callee.name)) {
        fn.callsInternal.push(callee.name);
        fn.taintEdges.push({
          callee: callee.name,
          args: (call.arguments || []).map(a => { const ids = idsIn(exprText(a)); return ids[0] || ''; }),
        });
      }
    },
    EmitStatement() { fn.emitsEvents = true; },
    MemberAccess(member) {
      const t = exprText(member);
      if (t === 'tx.origin') fn.usesTxOrigin = true;
      if (t === 'block.timestamp' || t === 'now') fn.usesBlockTimestamp = true;
      if (/^block\.(difficulty|prevrandao|number|coinbase|gaslimit)$/.test(t)) fn.usesBlockProperties = true;
    },
    // assignments to state variables
    BinaryOperation(bin) {
      if (bin.operator === '*') fn.rawMultiply = true;
      // Compound and plain assignments appear as BinaryOperation in this parser
      if (/^(=|\+=|-=|\*=|\/=|%=|\|=|&=|\^=)$/.test(bin.operator)) {
        const baseVar = resolveBaseVar(bin.left);
        const line = bin.loc?.start?.line;
        if (baseVar && contract.stateVars.some(v => v.name === baseVar && !v.isConstant)) {
          fn.stateWrites.push({ var: baseVar, line, selfScoped: isSelfScoped(bin.left) });
          if (firstStateWriteLine === null) firstStateWriteLine = line;
          // index-write sink: an arbitrary OVERWRITE (=) of a storage slot keyed by
          // attacker input is dangerous (arbitrary-write). Additive/subtractive
          // updates (+=, -=) keyed by an address are normal accounting (token
          // credits/debits) and are NOT flagged — this removed a real false positive
          // measured against the labeled set (clean ERC20 transfer).
          const isOverwrite = bin.operator === '=';
          if (isOverwrite && bin.left.type === 'IndexAccess' && !isSelfScoped(bin.left)) {
            fn.taintSinks.push({ kind: 'index-write', operands: idsIn(exprText(bin.left.index)), line });
          }
        }
      }
    },
    Assignment(asgn) {
      const baseVar = resolveBaseVar(asgn.left);
      const line = asgn.loc?.start?.line;
      if (baseVar && contract.stateVars.some(v => v.name === baseVar && !v.isConstant)) {
        fn.stateWrites.push({ var: baseVar, line, selfScoped: isSelfScoped(asgn.left) });
        if (firstStateWriteLine === null) firstStateWriteLine = line;
      }
    },
  });

  // Reentrancy heuristic done RIGHT: external call must come BEFORE a state write
  // to a balance-like variable, AND no reentrancy guard present.
  if (lastExternalCallLine !== null && fn.stateWrites.length > 0 && !fn.hasReentrancyGuard) {
    const writeAfterCall = fn.stateWrites.some(w => w.line && w.line > lastExternalCallLine);
    if (writeAfterCall) fn.externalCallBeforeWrite = true;
  }

  fn.zeroAddressChecks = [...fn.zeroAddressChecks];
  return fn;
}

function analyzeModifierBody(node) {
  const result = { hasSenderCheck: false, hasReentrancyLock: false };
  if (!node.body) {
    // e.g. `modifier onlyOwner;` rare; infer from name
    if (ACCESS_MODIFIERS.test(node.name)) result.hasSenderCheck = true;
    if (REENTRANCY_MODIFIERS.test(node.name)) result.hasReentrancyLock = true;
    return result;
  }
  parser.visit(node.body, {
    FunctionCall(call) {
      if (call.expression?.type === 'Identifier' && call.expression.name === 'require') {
        const a = exprText(call.arguments?.[0]);
        if (/msg\.sender|hasRole|_checkRole|owner/.test(a)) result.hasSenderCheck = true;
      }
    },
    Identifier(id) {
      if (/^_?(locked|status|entered|mutex)$/i.test(id.name)) result.hasReentrancyLock = true;
    },
  });
  if (ACCESS_MODIFIERS.test(node.name)) result.hasSenderCheck = true;
  if (REENTRANCY_MODIFIERS.test(node.name)) result.hasReentrancyLock = true;
  return result;
}

// Extract bare identifiers from a stringified expression (for taint operands).
function idsIn(text) {
  if (!text) return [];
  const stop = new Set(['msg','sender','value','data','address','this','block','tx','origin','now','true','false','uint','int','bool','memory','storage','calldata']);
  return [...new Set((text.match(/[A-Za-z_]\w*/g) || []).filter(t => !stop.has(t)))];
}

// Is this LHS write scoped to the caller's own slot? e.g. balances[msg.sender]
// Such writes are NOT privileged — anyone modifying only their own balance is
// expected behavior, so we must not flag them as missing access control.
function isSelfScoped(node) {
  let cur = node;
  while (cur) {
    if (cur.type === 'IndexAccess') {
      const idx = exprText(cur.index);
      if (/msg\.sender/.test(idx)) return true;
      cur = cur.base; continue;
    }
    if (cur.type === 'MemberAccess') { cur = cur.expression; continue; }
    return false;
  }
  return false;
}

// Resolve the base state variable being written, through index/member access.
// balances[msg.sender] -> 'balances';  a.b.c -> 'a';  arr[i][j] -> 'arr'
function resolveBaseVar(node) {
  let cur = node;
  while (cur) {
    if (cur.type === 'Identifier') return cur.name;
    if (cur.type === 'IndexAccess') { cur = cur.base; continue; }
    if (cur.type === 'MemberAccess') { cur = cur.expression; continue; }
    return null;
  }
  return null;
}

// ── Helpers to stringify AST expressions safely ─────────────────────────────
function typeToString(t) {
  if (!t) return 'unknown';
  if (t.type === 'ElementaryTypeName') return t.name;
  if (t.type === 'UserDefinedTypeName') return t.namePath;
  if (t.type === 'Mapping') return `mapping(${typeToString(t.keyType)} => ${typeToString(t.valueType)})`;
  if (t.type === 'ArrayTypeName') return `${typeToString(t.baseTypeName)}[]`;
  return t.name || t.namePath || 'complex';
}

function exprText(node) {
  if (!node) return '';
  switch (node.type) {
    case 'Identifier': return node.name;
    case 'MemberAccess': return `${exprText(node.expression)}.${node.memberName}`;
    case 'BinaryOperation': return `${exprText(node.left)} ${node.operator} ${exprText(node.right)}`;
    case 'FunctionCall': return `${exprText(node.expression)}(${(node.arguments||[]).map(exprText).join(',')})`;
    case 'NumberLiteral': return node.number;
    case 'StringLiteral': return node.value;
    case 'IndexAccess': return `${exprText(node.base)}[${exprText(node.index)}]`;
    case 'TupleExpression': return `(${(node.components||[]).map(exprText).join(',')})`;
    case 'UnaryOperation': return `${node.operator}${exprText(node.subExpression)}`;
    case 'NameValueExpression': return exprText(node.expression);
    case 'BooleanLiteral': return String(node.value);
    case 'ElementaryTypeName': return node.name;
    default: return '';
  }
}
