# ADR-0006: Fail-open datapath, fail-closed control

- **Status:** Accepted
- **Date:** 2026-09-27

## Decision
- If inference or the control plane fails, nodes keep enforcing their **last-known-good signed
  bundle** (persisted on disk and restored at start) plus cached dynamic verdicts until TTL.
- If a new bundle fails to apply, the previous nftables ruleset stays in force (atomic apply).
- If a bundle fails signature, schema or version checks, it is rejected (fail-closed control).
- If the agent process dies, traffic passes (fail-open availability).

## Consequences
Availability is preferred over enforcement by default. High-security zones can pair the nftables
backend with a default-deny ruleset managed outside NeuraWall.
