# ADR-0008: Python implementation, central inference, services layer

- **Status:** Accepted
- **Date:** 2026-09-27

## Context
The blueprint assumes Rust for the collector, Tier 1, policy engine and node agent, with Tier 1/2
on every node. Release 1.0 optimises for a small team shipping a supportable product quickly.

## Decision
1. **Python 3.12 throughout** (FastAPI, SQLAlchemy, scikit-learn, pydantic), React/TypeScript for
   the console. Performance-critical work is vectorised (Tier 1 scores flows in batches:
   ~0.06 ms/flow measured) or delegated to the kernel (nftables).
2. **Tier 1/2 run centrally** in the control plane on flows shipped by nodes; nodes enforce
   static rules locally and apply dynamic verdicts returned with each batch. The policy engine
   used for a node's flows matches the bundle version that node has applied.
3. **`services` layer**: control plane and node agent are composition roots in their own layer,
   so domain modules can stay mutually independent (blueprint lists them as modules).

## Consequences
- (+) One codebase, one language for detectors and policy; single warm baseline; small agents.
- (−) Inference adds a control-plane round-trip before dynamic verdicts apply (seconds, not µs).
  First-packet enforcement relies on static rules.
- (−) The control plane is a single process (in-memory baselines); it scales vertically.
- The protocol boundaries (bundles, verdicts, flow schema) are language-neutral, so a Rust
  agent or node-side Tier 1 can replace components without changing the contract.
