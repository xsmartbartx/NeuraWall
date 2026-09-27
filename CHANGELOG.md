# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-09-27

First release.

### Added
- Control plane with REST API, operator console, PostgreSQL/SQLite persistence and automatic migrations.
- Tier 1 anomaly engine (Isolation Forest, EWMA baselines, DNS entropy, flood/scan detection).
- Tier 2 L7 classifier: SQL/command/template injection, path traversal, XSS, DGA, DNS tunnelling,
  C2 beaconing, exfiltration, TLS fingerprint mismatch; attributions for every detection.
- Tier 3 Claude advisor (alert triage, rule drafting, incident narration, verdict explanation)
  with prompt-injection guardrails, hourly budget, refusal fallbacks and an offline advisor.
- Policy engine: first-match rule arbitration, alert-only mode, hygiene analysis (shadowed,
  redundant, overly broad), blast-radius simulation on legitimate traffic.
- Ed25519-signed policy bundles, node-side verification with pinned keys and anti-replay,
  canary rollout (5/25/100%) with automatic rollback.
- Node agent with Zeek and JSONL flow sources, nftables and dry-run datapaths, last-known-good
  persistence.
- RBAC (viewer, analyst, operator, approver, admin), optional four-eyes approval, session
  revocation, hash-chained audit trail with verification.
- Docker image, Compose stack (PostgreSQL + Caddy TLS), Helm chart, systemd units.
- Demo mode and synthetic traffic generator.
