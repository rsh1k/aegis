import fs from 'fs';
import path from 'path';
import axios from 'axios';

const ETHERSCAN_APIS = {
  ethereum: 'https://api.etherscan.io/api',
  base:     'https://api.basescan.org/api',
  arbitrum: 'https://api.arbiscan.io/api',
  polygon:  'https://api.polygonscan.com/api',
  optimism: 'https://api-optimistic.etherscan.io/api',
  bsc:      'https://api.bscscan.com/api',
};

export async function fetchSource(target, network = 'ethereum') {
  const lc = target.toLowerCase();

  // ── On-chain address (check first; unambiguous format) ───────────
  if (/^0x[0-9a-fA-F]{40}$/.test(target)) {
    return fetchFromChain(target, network);
  }

  // ── Local .sol file or folder ────────────────────────────────────
  if (lc.endsWith('.sol') || fs.existsSync(target)) {
    if (!fs.existsSync(target)) {
      throw new Error(`File not found: "${target}". Check the path and try again.`);
    }
    const stat = fs.statSync(target);
    if (stat.isDirectory()) {
      return fetchFolder(target);
    }
    const code = fs.readFileSync(target, 'utf8');
    return {
      type: 'file',
      name: path.basename(target).replace(/\.sol$/, ''),
      source: code,
      files: [{ name: path.basename(target), code }],
    };
  }

  // ── Folder of .sol files ─────────────────────────────────────────
  if (fs.existsSync(target) && fs.statSync(target).isDirectory()) {
    return fetchFolder(target);
  }

  throw new Error(`Cannot resolve target: "${target}"\nExpected: 0x address, .sol file, or folder path`);
}

function fetchFolder(dir) {
  const files = [];
  function walk(d) {
    for (const f of fs.readdirSync(d)) {
      const full = path.join(d, f);
      if (fs.statSync(full).isDirectory()) { walk(full); continue; }
      if (f.endsWith('.sol')) {
        files.push({ name: path.relative(dir, full), code: fs.readFileSync(full, 'utf8') });
      }
    }
  }
  walk(dir);
  if (files.length === 0) throw new Error(`No .sol files found in ${dir}`);
  return {
    type: 'folder',
    name: path.basename(dir),
    source: files.map(f => `// === ${f.name} ===\n${f.code}`).join('\n\n'),
    files,
  };
}

async function fetchFromChain(address, network) {
  const baseUrl = ETHERSCAN_APIS[network.toLowerCase()];
  if (!baseUrl) throw new Error(`Unknown network: ${network}`);

  // Try without API key first (rate-limited but works for demos)
  const url = `${baseUrl}?module=contract&action=getsourcecode&address=${address}`;

  const resp = await axios.get(url, { timeout: 15000 });
  const data = resp.data;

  if (data.status !== '1' || !data.result?.[0]) {
    throw new Error(`Contract not found on ${network}. Is it verified on Etherscan?`);
  }

  const result = data.result[0];
  if (!result.SourceCode || result.SourceCode === '') {
    throw new Error(`Contract source not verified on ${network}. Upload your .sol file directly instead.`);
  }

  let files = [];
  let source = result.SourceCode;

  // Handle multi-file JSON format
  if (source.startsWith('{{') || source.startsWith('{')) {
    try {
      const cleaned = source.startsWith('{{') ? source.slice(1, -1) : source;
      const parsed  = JSON.parse(cleaned);
      const sources = parsed.sources || parsed;
      files = Object.entries(sources).map(([name, obj]) => ({
        name,
        code: typeof obj === 'string' ? obj : obj.content,
      }));
      source = files.map(f => `// === ${f.name} ===\n${f.code}`).join('\n\n');
    } catch {
      files = [{ name: `${address}.sol`, code: source }];
    }
  } else {
    files = [{ name: `${address}.sol`, code: source }];
  }

  return {
    type: 'address',
    name: result.ContractName || address,
    address,
    network,
    compiler: result.CompilerVersion,
    source,
    files,
  };
}
