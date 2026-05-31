// ─────────────────────────────────────────────────────────────────────────────
// Benchmark category mapping
// SmartBugs Curated uses the DASP taxonomy (// <yes> <report> CATEGORY markers).
// Aegis emits OWASP SC Top 10 (2026) IDs. This maps between them so we can
// score detections against ground-truth labels.
//
// DASP categories in the dataset directory names:
//   reentrancy, access_control, arithmetic, unchecked_low_level_calls,
//   denial_of_service, bad_randomness, front_running, time_manipulation,
//   short_addresses, other
// ─────────────────────────────────────────────────────────────────────────────

// Map each DASP category -> the OWASP SC 2026 IDs Aegis would emit for it.
// A detection "counts" for a labeled contract if Aegis reports ANY of the
// mapped OWASP IDs.
export const DASP_TO_OWASP = {
  reentrancy:                ['SC08:2026'],
  access_control:            ['SC01:2026'],
  arithmetic:                ['SC07:2026', 'SC09:2026'],
  unchecked_low_level_calls: ['SC06:2026'],
  denial_of_service:         ['SC02:2026'],          // DoS detector tagged SC02 in our engine
  bad_randomness:            ['SC02:2026'],          // weak-randomness detector tagged SC02
  front_running:             ['SC02:2026'],          // no dedicated detector; logic family
  time_manipulation:         ['SC02:2026'],          // timestamp detector tagged SC02
  short_addresses:           [],                     // not detectable from source (ABI-level)
  other:                     [],                     // unspecified; excluded from scoring
};

// Categories we make NO claim to detect. Excluded from recall scoring so the
// benchmark is honest about scope rather than penalizing undetectable classes.
export const OUT_OF_SCOPE = ['short_addresses', 'other'];

// Human-readable labels for the report.
export const DASP_LABELS = {
  reentrancy:                'Reentrancy',
  access_control:            'Access Control',
  arithmetic:                'Arithmetic',
  unchecked_low_level_calls: 'Unchecked Low-Level Calls',
  denial_of_service:         'Denial of Service',
  bad_randomness:            'Bad Randomness',
  front_running:             'Front Running',
  time_manipulation:         'Time Manipulation',
  short_addresses:           'Short Addresses (out of scope)',
  other:                     'Other (out of scope)',
};
