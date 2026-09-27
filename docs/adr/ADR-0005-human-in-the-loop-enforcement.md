# ADR-0005: Human-in-the-loop enforcement

- **Status:** Accepted
- **Date:** 2026-09-27

## Decision
The LLM produces `RuleDraft`s, never `Rule`s. Drafts are schema-validated, forced to alert-only,
de-duplicated, and simulated against recent legitimate traffic before a human sees them. Only a
user with the `rules:approve` permission can turn a draft into a rule, choosing alert-only or
enforce and leaving an audited note. Enforcing a rule whose blast radius exceeds the threshold
requires explicit acknowledgement. With `policy.require_four_eyes`, the approver must differ
from the author.

## Consequences
- (+) A successful prompt injection can at most produce a misleading draft.
- (−) Containment waits for a human. The starter pack's high-confidence injection rule enforces
  from day one to cover the most common case without waiting.
