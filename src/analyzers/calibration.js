// ─────────────────────────────────────────────────────────────────────────────
// Confidence calibration
// Every detector carries a precision number AND a provenance flag:
//   provenance: 'measured'  → validated against a labeled ground-truth set
//   provenance: 'estimated' → a prior, NOT yet validated (treat with caution)
//
// This distinction is deliberate and load-bearing: an estimated number that
// looks like a measurement is worse than no number, because it invites false
// trust. The report surfaces provenance so nobody mistakes a guess for evidence.
//
// Measured sources:
//   - semantic detectors: SmartBugs Curated (143 labeled contracts)
//   - taint detectors:     benchmark/taint-labeled (run: npm run validate-taint)
// Estimated detectors are marked accordingly until a labeled set exists.
// ─────────────────────────────────────────────────────────────────────────────

const CALIBRATION = {
  // ── TAINT: MEASURED against benchmark/taint-labeled (10 contracts) ──
  'TAINT-delegatecall-target': { precision: 1.00, recall: 1.00, samples: 2, provenance: 'measured' },
  'TAINT-call-target':         { precision: 1.00, recall: 1.00, samples: 2, provenance: 'measured' },
  'TAINT-index-write':         { precision: 1.00, recall: 1.00, samples: 2, provenance: 'measured' },
  'TAINT-selfdestruct-arg':    { precision: 1.00, recall: 1.00, samples: 1, provenance: 'measured' },
  'TAINT-unchecked-arithmetic':{ precision: 0.55, recall: null, samples: 0, provenance: 'estimated' },

  // ── SEMANTIC: MEASURED against SmartBugs Curated ──
  'SEM-reentrancy':        { precision: 0.94, recall: 0.52, samples: 31, provenance: 'measured' },
  'SEM-access-control':    { precision: 0.78, recall: 0.50, samples: 18, provenance: 'measured' },
  'SEM-tx-origin':         { precision: 0.96, recall: null, samples: 12, provenance: 'measured' },
  'SEM-selfdestruct':      { precision: 0.88, recall: null, samples: 9,  provenance: 'measured' },
  'SEM-randomness':        { precision: 0.80, recall: 0.50, samples: 8,  provenance: 'measured' },
  'SEM-overflow':          { precision: 0.62, recall: 0.93, samples: 15, provenance: 'measured' },

  // ── SEMANTIC: ESTIMATED (no labeled subset yet) ──
  'SEM-init':              { precision: 0.85, recall: null, samples: 0, provenance: 'estimated' },
  'SEM-delegatecall':      { precision: 0.74, recall: null, samples: 0, provenance: 'estimated' },

  // ── REGEX net: MEASURED (SmartBugs, noisier) ──
  'AC-missing-modifier':   { precision: 0.45, recall: null, samples: 20, provenance: 'measured' },
  'RE-external-before-state': { precision: 0.60, recall: null, samples: 18, provenance: 'measured' },
  'AR-old-solidity':       { precision: 0.35, recall: null, samples: 40, provenance: 'measured' },

  // ── REGEX net: ESTIMATED ──
  'OR-spot-price':         { precision: 0.55, recall: null, samples: 0, provenance: 'estimated' },

  // ── FORMAL: high by construction, but 0 samples run here ──
  'SMT-formal':            { precision: 0.97, recall: null, samples: 0, provenance: 'estimated' },
};

const NEUTRAL = { precision: 0.5, recall: null, samples: 0, provenance: 'estimated' };

export function calibrate(finding) {
  const c = CALIBRATION[finding.detectorId] || NEUTRAL;
  let band;
  if (c.precision >= 0.8) band = 'HIGH';
  else if (c.precision >= 0.55) band = 'MEDIUM';
  else band = 'LOW';
  return {
    ...finding,
    precision: c.precision,
    precisionProvenance: c.provenance,
    precisionSamples: c.samples,
    confidence: finding.confidence === 'HIGH' ? 'HIGH' : band,
  };
}

export function calibrateAll(findings) {
  return findings.map(calibrate);
}

export function getCalibrationTable() {
  return CALIBRATION;
}

// Summary for reporting: how much of the calibration is actually measured.
export function calibrationProvenanceSummary() {
  const all = Object.values(CALIBRATION);
  const measured = all.filter(c => c.provenance === 'measured').length;
  return { total: all.length, measured, estimated: all.length - measured };
}
