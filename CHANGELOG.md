# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.1.0] — 2026-09-27

### Added
- Plans and Stripe billing, modelled on Vigilo: Community (free), Pro ($149/mo), Business ($499/mo),
  Enterprise ($3,000/mo) self-serve through Stripe Checkout (monthly or yearly, two months free),
  Enterprise Dedicated by licence. Stripe Customer Portal for plan changes, cards and invoices.
- Entitlements are enforced: enrolled-node limit, plan-based flow retention, Claude AI advisor on
  paid plans only. Unknown or lapsed plans fail closed to Community (3-day renewal grace).
- Signed Stripe webhook (`/api/v1/billing/webhook`) that applies only this installation's
  subscriptions on a shared Stripe account; console Billing page; audit entries for billing changes.

### Changed
- `flow_retention_seconds` is now an optional override; by default the plan sets retention.

## [1.0.1] — 2026-09-27

### Fixed
- Release image build: the console is now built once on the native build platform instead of
  under arm64 emulation, which stalled the multi-arch build.

### Changed
- CI and release workflows use Node 24 versions of all GitHub Actions.
- License metadata reflects the proprietary license.

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
