// ─────────────────────────────────────────────────────────────────────────────
// Enterprise config + audit trail
//  - API key encrypted at rest (AES-256-GCM) with a machine-derived key
//  - Append-only, hash-chained audit log (tamper-evident) — NIST RV / AU
//
// Note: machine-derived encryption protects against casual disk inspection and
// accidental key commits. It is NOT a substitute for a real secrets manager
// (Vault, AWS Secrets Manager). Enterprise deployments should set
// ANTHROPIC_API_KEY via their secrets manager and skip stored keys entirely.
// ─────────────────────────────────────────────────────────────────────────────

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import os from 'os';

export const CONFIG_DIR  = path.join(os.homedir(), '.aegis');
export const CONFIG_FILE = path.join(CONFIG_DIR, 'config.enc');
export const AUDIT_LOG   = path.join(CONFIG_DIR, 'audit.log');

// Derive a key from stable machine + user attributes. Best-effort obfuscation.
function machineKey() {
  const material = [os.hostname(), os.userInfo().username, os.platform(), os.arch()].join('|');
  return crypto.createHash('sha256').update(material + '::aegis-v2').digest();
}

export function saveConfig(obj) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', machineKey(), iv);
  const enc = Buffer.concat([cipher.update(JSON.stringify(obj), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  const blob = Buffer.concat([iv, tag, enc]).toString('base64');
  fs.writeFileSync(CONFIG_FILE, blob, { mode: 0o600 });
}

export function loadConfig() {
  try {
    if (!fs.existsSync(CONFIG_FILE)) return {};
    const blob = Buffer.from(fs.readFileSync(CONFIG_FILE, 'utf8'), 'base64');
    const iv = blob.subarray(0, 12);
    const tag = blob.subarray(12, 28);
    const enc = blob.subarray(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', machineKey(), iv);
    decipher.setAuthTag(tag);
    const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
    return JSON.parse(dec.toString('utf8'));
  } catch {
    return {};
  }
}

// ── Tamper-evident audit log ────────────────────────────────────────────────
// Each entry includes a hash of the previous entry, forming a chain. Any edit
// to a past entry breaks every subsequent hash — detectable via verifyAuditLog.
export function auditAppend(event) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });

  let prevHash = 'GENESIS';
  if (fs.existsSync(AUDIT_LOG)) {
    const lines = fs.readFileSync(AUDIT_LOG, 'utf8').trim().split('\n').filter(Boolean);
    if (lines.length) {
      try { prevHash = JSON.parse(lines[lines.length - 1]).hash; } catch {}
    }
  }

  const entry = {
    ts: new Date().toISOString(),
    event: event.type,
    target: event.target ? redactTarget(event.target) : undefined,
    findings: event.findings,
    score: event.score,
    actor: os.userInfo().username,
    prevHash,
  };
  entry.hash = crypto.createHash('sha256')
    .update(JSON.stringify({ ...entry, hash: undefined }))
    .digest('hex');

  fs.appendFileSync(AUDIT_LOG, JSON.stringify(entry) + '\n', { mode: 0o600 });
  return entry.hash;
}

export function verifyAuditLog() {
  if (!fs.existsSync(AUDIT_LOG)) return { valid: true, entries: 0 };
  const lines = fs.readFileSync(AUDIT_LOG, 'utf8').trim().split('\n').filter(Boolean);
  let prevHash = 'GENESIS';
  for (let i = 0; i < lines.length; i++) {
    let entry;
    try {
      entry = JSON.parse(lines[i]);
    } catch {
      return { valid: false, entries: lines.length, brokenAt: i + 1, reason: 'malformed entry' };
    }
    const recomputed = crypto.createHash('sha256')
      .update(JSON.stringify({ ...entry, hash: undefined }))
      .digest('hex');
    if (entry.prevHash !== prevHash || entry.hash !== recomputed) {
      return { valid: false, entries: lines.length, brokenAt: i + 1, reason: 'hash chain broken' };
    }
    prevHash = entry.hash;
  }
  return { valid: true, entries: lines.length };
}

// Don't write full local paths or full addresses to the audit log unnecessarily.
function redactTarget(t) {
  if (/^0x[0-9a-fA-F]{40}$/.test(t)) return t.slice(0, 10) + '…' + t.slice(-4);
  return path.basename(t);
}
