// ─────────────────────────────────────────────────────────────────────────────
// Provider configuration
// Manages the set of AI scanners available to the panel. Keys are stored
// encrypted (via secure-config). Each provider entry:
//   { id, type: 'anthropic'|'openai'|'openai-compatible', model, label, baseURL? }
// API keys are stored separately keyed by provider id.
// ─────────────────────────────────────────────────────────────────────────────

import { loadConfig, saveConfig } from '../utils/secure-config.js';

// Sensible defaults so `--panel` works once keys are present.
export const DEFAULT_PROVIDERS = [
  { id: 'anthropic', type: 'anthropic', model: 'claude-sonnet-4-20250514', label: 'Claude (Sonnet)' },
  { id: 'openai', type: 'openai', model: 'gpt-4o', label: 'GPT-4o' },
  // Local, free, private. Override the model via config; pull it first with `ollama pull`.
  { id: 'ollama', type: 'ollama', model: 'gemma2', label: 'Ollama (local: gemma2)', baseURL: 'http://localhost:11434/v1' },
];

// Resolve which providers to actually run, given CLI flags + stored config + env.
// Returns only providers that have a usable API key (Ollama needs none).
export function resolveProviders({ panel, providerList } = {}) {
  const cfg = loadConfig();
  const configured = cfg.providers && cfg.providers.length ? cfg.providers : DEFAULT_PROVIDERS;

  // Filter by explicit --provider list if given
  let selected = configured;
  if (providerList) {
    const wanted = providerList.split(',').map(s => s.trim().toLowerCase());
    selected = configured.filter(p => wanted.includes(p.id.toLowerCase()) || wanted.includes(p.type.toLowerCase()));
  } else if (!panel) {
    // Non-panel: just the first available (back-compat single-model behavior)
    selected = configured.slice(0, 1);
  }

  // Attach keys; Ollama is local and needs none, so it always passes.
  const withKeys = [];
  for (const p of selected) {
    if (p.type === 'ollama') { withKeys.push({ ...p, apiKey: 'ollama' }); continue; }
    const key = providerKey(p, cfg);
    if (key) withKeys.push({ ...p, apiKey: key });
  }
  return withKeys;
}

function providerKey(provider, cfg) {
  // Local models require no key.
  if (provider.type === 'ollama') return 'ollama';
  // Env var precedence (enterprise: use secrets manager)
  if (provider.type === 'anthropic') {
    if (process.env.ANTHROPIC_API_KEY) return process.env.ANTHROPIC_API_KEY;
  }
  if (provider.type === 'openai' || provider.type === 'openai-compatible') {
    if (process.env.OPENAI_API_KEY) return process.env.OPENAI_API_KEY;
  }
  // Stored per-provider key, then legacy single apiKey for anthropic
  if (cfg.providerKeys && cfg.providerKeys[provider.id]) return cfg.providerKeys[provider.id];
  if (provider.type === 'anthropic' && cfg.apiKey) return cfg.apiKey;
  return null;
}

// Persist a provider key (used by `aegis config`).
export function setProviderKey(providerId, key) {
  const cfg = loadConfig();
  cfg.providerKeys = cfg.providerKeys || {};
  cfg.providerKeys[providerId] = key;
  saveConfig(cfg);
}

export function listConfiguredProviders() {
  const cfg = loadConfig();
  const providers = cfg.providers && cfg.providers.length ? cfg.providers : DEFAULT_PROVIDERS;
  return providers.map(p => ({
    ...p,
    hasKey: !!providerKey(p, cfg),
  }));
}
