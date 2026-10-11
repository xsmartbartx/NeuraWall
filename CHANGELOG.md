# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Rules page: how many flows each rule matched in the last 7 days and when it last did ("never" makes dead rules visible),
  and a "Replay against recent traffic" card in the rule drawer showing its blast radius. New `GET /rules/stats` and
  `GET /rules/{id}/impact`.
- Rules page: a "Clean up…" action on shadowed and redundant findings (a rule that can never match because an earlier
  rule covers its traffic). It disables the rule, which changes no verdict, after a confirmation that shows recent matches.
  It is the existing audited rule update, so it publishes a signed bundle and stays reversible.

### Changed
- Web-injection labels (SQL, command and template injection, path traversal, XSS) now raise an alert from a Tier 2
  confidence of 0.5 instead of 0.7, because a single strong payload scores 0.5 to 0.62 (docs/evasion-report.md). Other
  labels keep 0.7; on synthetic benign traffic a global 0.5 would have alerted on 1.3% of flows (DNS DGA). Nothing blocks
  differently: blocking still needs an approved rule (the starter rule asks for 0.9). New setting
  `policy.classifier_alert_threshold` (default 0.7, minimum 0.3); it applies to bundles published from now on.

### Added
- Erase a person: `DELETE /users/{id}` and an Erase action on the Users page. The audit trail now records people as
  `user:<id>` instead of an email, so erasing is possible without breaking the hash chain. Older entries may still
  hold an email (see docs/security.md).
- Console keyboard access: table rows that open a drawer take Tab, Enter and Space; dialogs move focus in, keep Tab
  inside, close on Escape and return focus; the verdict chart has a text summary and meters are progress bars.
- Linked mode (optional): an installation can belong to one NEXORA organisation. The plan is pulled from
  NEXORA, usage events (counts only) go back through an outbox (queued in memory, persisted within about 15 s, retried; a crash can lose the last few seconds), and a plan change never changes
  what nodes enforce. See [docs/nexora.md](docs/nexora.md).
- Just-in-time users: with `auth.sso_jit`, a verified member of the required organisation signs in without
  an admin creating the account first. They start as viewers; roles never come from the identity provider.
  `auth.local_login=admin_only` keeps password sign-in for admins only.
- Claude metering: every call that reaches the model is counted. Business and Enterprise get a monthly call
  budget (the offline advisor answers once it is used); Pro uses the customer's own Anthropic key.
- Webhook notifications (Integrations page): signed, SSRF-safe, with retries and a delivery log.
- CSV export of flows, alerts and the audit trail, safe against spreadsheet formula injection.
- Public demo sign-in for a separate demo instance (`auth.demo_public_login`).
- Console contrast fixed to WCAG AA in both themes (new `--border-input` role for form fields).

### Fixed
- `last_login` and a newly linked SSO identity were never saved (the user was detached from the session
  before the update was flushed).
- `docs/security.md` said the console had no SSO button.

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
