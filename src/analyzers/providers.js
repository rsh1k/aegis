// ─────────────────────────────────────────────────────────────────────────────
// AI provider adapters
// A provider-agnostic layer so multiple AI models can audit the same contract
// and return findings in ONE normalized schema. Each adapter knows how to call
// its API; the rest of the system treats them identically.
//
// Real, callable providers only:
//   - anthropic  : Claude (Messages API)
//   - openai     : GPT models (Chat Completions API)
//   - openai-compatible : any endpoint speaking the OpenAI schema
//        (covers most self-hosted / third-party gateways — set baseURL)
//
// NOTE: "model names" like a security-specialized variant are just the model
// string you pass; we don't hardcode or invent endpoints that don't exist.
// ─────────────────────────────────────────────────────────────────────────────

import axios from 'axios';

// The shared audit instruction. Identical across providers so results are
// comparable — differences then reflect the MODEL, not the prompt.
export function buildAuditPrompt(source, staticFindings, metrics) {
  const known = staticFindings.length
    ? staticFindings.slice(0, 20).map(f => `- [${f.severity}] ${f.title} (${f.owasp || '?'})`).join('\n')
    : '- none';
  return `You are a senior smart-contract security auditor. Review this Solidity for vulnerabilities, thinking about business logic, access control, economic/flash-loan attacks, oracle manipulation, reentrancy, and upgradeability. For each issue assess exploitability and whether a mitigating control already exists.

CONTRACT:
\`\`\`solidity
${source.slice(0, 7000)}${source.length > 7000 ? '\n...[truncated]' : ''}
\`\`\`

CONTEXT: Solidity ${metrics.solidityVersion}; functions ${metrics.functions}.
STATIC TOOL ALREADY FOUND:
${known}

Find issues the static tool may have MISSED, and confirm/deny the ones above.
Return ONLY valid JSON, no markdown fences:
{
  "summary": "<2-3 sentence security posture>",
  "findings": [
    {
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "title": "<short>",
      "function": "<function name or 'contract'>",
      "owasp": "SC0X:2026",
      "cwe": "CWE-XXX",
      "exploitability": "<one line: how an attacker triggers it>",
      "requiresAuth": <true|false>,
      "mitigationPresent": <true|false>,
      "description": "<why exploitable>",
      "fix": "<concrete remediation>"
    }
  ]
}`;
}

function safeParseFindings(text) {
  const clean = (text || '').replace(/```json|```/g, '').trim();
  try {
    const obj = JSON.parse(clean.slice(clean.indexOf('{')));
    return {
      summary: obj.summary || '',
      findings: (obj.findings || []).map(normalizeFinding),
    };
  } catch {
    return { summary: 'Model output could not be parsed as JSON.', findings: [] };
  }
}

function normalizeFinding(f) {
  return {
    severity: (f.severity || 'MEDIUM').toUpperCase(),
    title: f.title || 'Unspecified issue',
    function: f.function || 'contract',
    owasp: f.owasp || null,
    cwe: f.cwe || null,
    exploitability: f.exploitability || '',
    requiresAuth: !!f.requiresAuth,
    mitigationPresent: !!f.mitigationPresent,
    description: f.description || '',
    fix: f.fix || '',
  };
}

// ── Anthropic (Claude) ──────────────────────────────────────────────────────
async function callAnthropic({ apiKey, model, prompt, timeout }) {
  const res = await axios.post(
    'https://api.anthropic.com/v1/messages',
    { model, max_tokens: 3000, messages: [{ role: 'user', content: prompt }] },
    { headers: { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' }, timeout }
  );
  return res.data.content?.map(c => c.text || '').join('') || '';
}

// ── OpenAI / OpenAI-compatible (GPT, gateways) ──────────────────────────────
async function callOpenAICompatible({ apiKey, model, prompt, timeout, baseURL }) {
  const url = (baseURL || 'https://api.openai.com/v1') + '/chat/completions';
  const res = await axios.post(
    url,
    { model, max_tokens: 3000, messages: [{ role: 'user', content: prompt }] },
    { headers: { Authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' }, timeout }
  );
  return res.data.choices?.[0]?.message?.content || '';
}

// ── Ollama (local models — gemma, deepseek, llama, mistral, etc.) ───────────
// Ollama exposes an OpenAI-compatible endpoint at http://localhost:11434/v1.
// No API key is required (any string works). Runs fully on the user's machine:
// free, private, and source never leaves the host.
async function callOllama({ model, prompt, timeout, baseURL }) {
  const base = baseURL || 'http://localhost:11434/v1';
  const url = base.replace(/\/$/, '') + '/chat/completions';
  const res = await axios.post(
    url,
    { model, messages: [{ role: 'user', content: prompt }], stream: false },
    { headers: { Authorization: 'Bearer ollama', 'content-type': 'application/json' }, timeout }
  );
  return res.data.choices?.[0]?.message?.content || '';
}

// ── Public: run one provider ────────────────────────────────────────────────
export async function runProvider(provider, { source, staticFindings, metrics, timeout = 90000 }) {
  const prompt = buildAuditPrompt(source, staticFindings, metrics);
  const started = Date.now();
  try {
    let raw;
    if (provider.type === 'anthropic') {
      raw = await callAnthropic({ apiKey: provider.apiKey, model: provider.model, prompt, timeout });
    } else if (provider.type === 'openai' || provider.type === 'openai-compatible') {
      raw = await callOpenAICompatible({ apiKey: provider.apiKey, model: provider.model, prompt, timeout, baseURL: provider.baseURL });
    } else if (provider.type === 'ollama') {
      // Local models are slower; give them a generous timeout if caller used the default.
      const localTimeout = timeout === 90000 ? 300000 : timeout;
      raw = await callOllama({ model: provider.model, prompt, timeout: localTimeout, baseURL: provider.baseURL });
    } else {
      return { id: provider.id, ok: false, error: `Unknown provider type: ${provider.type}`, findings: [] };
    }
    const parsed = safeParseFindings(raw);
    return {
      id: provider.id,
      label: provider.label || provider.id,
      ok: true,
      ms: Date.now() - started,
      summary: parsed.summary,
      findings: parsed.findings,
    };
  } catch (e) {
    const status = e.response?.status;
    const connRefused = e.code === 'ECONNREFUSED' || /ECONNREFUSED|connect/i.test(e.message || '');
    let error;
    if (provider.type === 'ollama' && connRefused) {
      error = 'Ollama not reachable at ' + (provider.baseURL || 'http://localhost:11434') + ' — is it running? (start with "ollama serve" and pull a model, e.g. "ollama pull gemma2")';
    } else if (provider.type === 'ollama' && status === 404) {
      error = `model "${provider.model}" not found in Ollama — pull it first: "ollama pull ${provider.model}"`;
    } else {
      error = status === 401 ? 'auth failed (bad API key)' : status === 429 ? 'rate limited' : (e.message || 'request failed');
    }
    return {
      id: provider.id,
      label: provider.label || provider.id,
      ok: false,
      ms: Date.now() - started,
      error,
      findings: [],
    };
  }
}

// Run several providers in parallel. Returns array of provider results.
export async function runPanel(providers, ctx) {
  return Promise.all(providers.map(p => runProvider(p, ctx)));
}
