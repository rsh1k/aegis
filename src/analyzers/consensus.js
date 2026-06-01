// ─────────────────────────────────────────────────────────────────────────────
// Consensus / adjudication engine
// Takes findings from multiple AI providers (+ the local semantic engine) and
// cross-references them into a single deliberated view:
//   - clusters findings that describe the SAME issue (by OWASP class + function)
//   - assigns confidence by AGREEMENT (how many independent scanners flagged it)
//   - surfaces DISAGREEMENTS (one model says critical, another silent)
//   - produces a panel "discussion" summarizing where scanners converge/diverge
//
// Rationale: the smart-contract security field's consensus is that no single
// tool catches everything and multiple tools should be layered. Agreement across
// independent models is a strong precision signal; a unique flag is a lead to
// investigate, not dismiss.
// ─────────────────────────────────────────────────────────────────────────────

const SEV_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, NONE: 0 };

// Normalize a finding into a clustering key. Same OWASP class on the same
// function is treated as "the same issue" even if titles differ in wording.
function clusterKey(f) {
  const owasp = (f.owasp || 'UNCLASSIFIED').split(':')[0];
  const fn = (f.function || extractFn(f.location) || 'contract').toLowerCase();
  return `${owasp}::${fn}`;
}

function extractFn(loc) {
  if (!loc) return null;
  const m = String(loc).match(/\.([A-Za-z0-9_]+)\s*\(/) || String(loc).match(/\.([A-Za-z0-9_]+)/);
  return m ? m[1] : null;
}

function highestSeverity(sevs) {
  return sevs.reduce((a, b) => (SEV_RANK[b] > SEV_RANK[a] ? b : a), 'LOW');
}

// sources: array of { id, label, findings: [...] }  (AI providers)
// localFindings: findings from the deterministic semantic engine (counts as a scanner)
export function adjudicate(sources, localFindings = []) {
  // Treat the local semantic engine as one more independent scanner
  const scanners = [
    { id: 'aegis-semantic', label: 'Aegis Semantic Engine', findings: localFindings },
    ...sources.filter(s => s.ok).map(s => ({ id: s.id, label: s.label, findings: s.findings })),
  ];
  const scannerIds = scanners.map(s => s.id);
  const totalScanners = scanners.length;

  // Cluster
  const clusters = new Map();
  for (const scanner of scanners) {
    for (const f of scanner.findings) {
      const key = clusterKey(f);
      if (!clusters.has(key)) {
        clusters.set(key, {
          key,
          owasp: f.owasp || null,
          function: f.function || extractFn(f.location) || 'contract',
          titles: new Set(),
          severities: [],
          agreedBy: new Set(),
          details: [],
          fixes: new Set(),
        });
      }
      const c = clusters.get(key);
      c.titles.add(f.title);
      c.severities.push(f.severity);
      c.agreedBy.add(scanner.id);
      if (f.description) c.details.push({ by: scanner.label, text: f.description, exploit: f.exploitability, auth: f.requiresAuth, mitigation: f.mitigationPresent });
      if (f.fix) c.fixes.add(f.fix);
    }
  }

  // Score each cluster
  const adjudicated = [];
  for (const c of clusters.values()) {
    const agreement = c.agreedBy.size;
    const ratio = agreement / totalScanners;
    const consensusSeverity = highestSeverity(c.severities);

    // Confidence model: more independent scanners agreeing = higher confidence.
    let confidence;
    if (agreement >= 3 || ratio >= 0.66) confidence = 'HIGH';
    else if (agreement === 2 || ratio >= 0.4) confidence = 'MEDIUM';
    else confidence = 'LOW';

    const dissenters = scannerIds.filter(id => !c.agreedBy.has(id));

    adjudicated.push({
      owasp: c.owasp,
      function: c.function,
      title: [...c.titles][0],
      altTitles: [...c.titles].slice(1),
      severity: consensusSeverity,
      confidence,
      agreement,
      totalScanners,
      agreedBy: [...c.agreedBy],
      dissentedBy: dissenters,
      details: c.details,
      fixes: [...c.fixes],
    });
  }

  // Sort: severity desc, then agreement desc
  adjudicated.sort((a, b) =>
    (SEV_RANK[b.severity] - SEV_RANK[a.severity]) || (b.agreement - a.agreement)
  );

  return {
    scanners: scanners.map(s => ({ id: s.id, label: s.label, findingCount: s.findings.length })),
    totalScanners,
    clusters: adjudicated,
    discussion: buildDiscussion(adjudicated, scanners),
  };
}

// Produce a human-readable "panel discussion" of where scanners agree/disagree.
function buildDiscussion(clusters, scanners) {
  const unanimous = clusters.filter(c => c.agreement === c.totalScanners && c.totalScanners > 1);
  const contested = clusters.filter(c => c.agreement > 1 && c.agreement < c.totalScanners);
  const solo = clusters.filter(c => c.agreement === 1);

  const lines = [];

  if (scanners.length <= 1) {
    lines.push('Only one scanner ran — no cross-validation available. Add a second provider (e.g. --provider openai) for consensus scoring.');
    return { unanimous, contested, solo, lines };
  }

  if (unanimous.length) {
    lines.push(`All ${scanners.length} scanners agreed on ${unanimous.length} issue(s) — highest confidence: ${unanimous.map(c => c.title).slice(0, 4).join('; ')}.`);
  }
  if (contested.length) {
    lines.push(`${contested.length} issue(s) were flagged by some but not all scanners — worth manual review: ${contested.map(c => `${c.title} (${c.agreement}/${c.totalScanners})`).slice(0, 4).join('; ')}.`);
  }
  if (solo.length) {
    lines.push(`${solo.length} issue(s) were uniquely raised by a single scanner — treat as leads, not confirmed: ${solo.map(c => `${c.title} [${c.agreedBy[0]}]`).slice(0, 4).join('; ')}.`);
  }
  if (!unanimous.length && !contested.length && !solo.length) {
    lines.push('No issues were raised by any scanner.');
  }
  return { unanimous, contested, solo, lines };
}
