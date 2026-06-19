# Confidence Scoring Rubric

Severity and confidence are scored independently and never merged into one number.

## Severity
Set per-rule in `scripts/score.py:SEVERITY_BY_RULE`, based on impact-if-true:
- **Critical**: live credential/private key exposure, confirmed malicious payload,
  confirmed tool-poisoning description.
- **High**: high-likelihood injected/typosquat package, unsafe exec on
  externally-derived input, TLS verification disabled.
- **Medium**: unscoped but not obviously abused tool grant, debug-only config
  issues with limited blast radius, single weak signal needing review.
- **Low**: hygiene issues (unpinned dev dependency, verbose logging).
- **Info**: suppressed/allowlisted findings kept for audit trail.

## Confidence (0-100)
```
confidence = base_signal_strength
           + corroboration_bonus
           - context_discount
           - allowlist_discount
```

- `base_signal_strength`: set per detection rule (see each `scan_*.py` module);
  exact-format signature matches start high (85-98), heuristic/AST-pattern-only
  matches start medium (40-60), generic entropy/shape heuristics start low (30-40).
- `corroboration_bonus` (+10 to +25): independent rules firing on the same
  line/file for the same underlying risk (e.g., a secret-shaped string AND a
  variable name containing `secret`/`key`).
- `context_discount` (-30): file path contains `test/`, `fixture/`, `example/`,
  `sample/`, `mock/` or the value matches a known placeholder shape
  (`xxxx`, `<your-key-here>`, `00000000...`).
- `allowlist_discount` (-100, i.e. force to Info): an entry in the repo's
  `.audit-allowlist` matches this exact finding **and** the allowlist entry
  includes a reviewer name and an expiry date. Expired allowlist entries are
  ignored (treated as if absent) and the finding is re-scored at full confidence.

## Buckets
| Score | Bucket |
|---|---|
| ≥80 | Confirmed |
| 50-79 | Likely |
| 25-49 | Possible |
| <25 | Speculative (verbose mode only) |

## Promotion rule
A finding's confidence is promoted to ≥80 ("Confirmed") automatically only when
the optional, human-approved **network-verified pass** (SKILL.md step 3)
corroborates it — e.g., the suspected typosquat package is confirmed absent
from the legitimate registry under the expected maintainer, or the suspected
leaked key is confirmed live/active. Without that step, supply-chain and
dependency-confusion findings cap out at "Likely" by design, since they cannot
be fully confirmed offline.
