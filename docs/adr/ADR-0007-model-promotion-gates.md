# ADR-0007: Rule and model promotion gates

- **Status:** Accepted (rules); Proposed (models)
- **Date:** 2026-09-27

## Decision (rules, implemented)
Every rule change publishes a signed bundle that rolls out to 5%, 25% and then 100% of nodes
(stable hash buckets salted per version), with a minimum dwell time per stage. A stage
auto-rolls back if canary nodes block more than `policy.rollback_block_rate_increase` (default 2
percentage points) more traffic than the baseline, given at least 100 flows on each side.
Rollback republishes the previous rule set as a **new** version so node anti-replay holds.

## Decision (models, proposed)
Supervised Tier 2 models will ship as signed model bundles with a 7-day shadow deployment and
an evaluation gate against the golden corpus, as in blueprint §6.3.
