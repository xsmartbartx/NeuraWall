# ADR-0001: Core architecture model

- **Status:** Accepted
- **Date:** 2026-09-27

## Context
The system combines enforcement, three inference tiers and a control plane. Without hard
boundaries, inference code tends to leak into enforcement paths and make the system unauditable.

## Decision
Five layers with one-way dependencies: **core ← security ← modules ← services ← cli**
(documentation describes all). Domain modules are mutually independent; only services compose
them. The policy engine is the single component that turns signals into enforcement actions.
Boundaries are enforced by `import-linter` contracts in CI, including a contract that the LLM
advisor can never import the policy engine, datapath or services.

## Consequences
- (+) Every enforced drop traces to one rule, one component and one audit entry.
- (+) Layer erosion fails CI instead of accumulating silently.
- (−) Some wiring code lives in the service layer rather than in modules.

## Alternatives considered
Convention-only boundaries (rejected: not enforceable under delivery pressure).
