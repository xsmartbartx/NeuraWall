# Architecture: NeuraWall x NEXORA Core ("linked mode")

Reads: `replica/recon.md`, `replica/features.csv`, `../NEXORA/docs/NEXORA-PLATFORM-ARCHITECTURE.md` (§4 contracts C-AUTH / C-ENT / C-EVENT, §4.3 Tenant Contract),
`../NEXORA/packages/billing/src/vigilo-sync.ts` (the existing precedent for a non-native product). Date: 2026-10-10.

Goal: close the 13 `clone=no` rows of the feature matrix without breaking what 1.1.0 already does well. NeuraWall is the product; this is the seam.

## Decisions (each one a short ADR in `docs/adr/` when built)

| # | decision | why | rejected |
| --- | --- | --- | --- |
| D1 | **Keep the stack.** Python 3.12, FastAPI, SQLAlchemy 2 + Alembic, PostgreSQL or SQLite, React + Vite console, single process | 1.1.0 is live, 131 tests, import-linter layers. The skill's default stack (Next.js, Supabase) would be a rewrite for no feature | rewrite |
| D2 | **Single-org per installation, bound to one NEXORA org.** Add `nexora.org_id`, not a tenant column | NeuraWall's baselines, Tier 3 queue, signing key and audit chain are per installation. Multi-tenant means `org_id` on every table plus per-org keys and engines: an XL project for a product that customers self-host | multi-tenant SaaS (ADR-0009, "not now") |
| D3 | **Linked mode is optional and off by default.** Standalone installs (no NEXORA account) work exactly as today, including their own Stripe | The README sells self-hosting; air-gapped customers exist | making NEXORA mandatory |
| D4 | **Pull, not push, for the plan.** The installation polls Core with an org API key (`nx_live_...`, scope `neurawall:link`) | Vigilo's push (HMAC to `/v1/internal/org-plan`) needs Core to reach the product. A self-hosted control plane is behind the customer's firewall. Pull works from anywhere and fails closed with the existing 3-day grace | push |
| D5 | **Core owns the subscription in linked mode.** NeuraWall's own checkout is disabled when linked; the plan arrives as a `subscriptions` row with `provider='nexora'` | One bill, one portal, no double billing on the shared Stripe account | two Stripe flows at once |
| D6 | **Identity: SSO with just-in-time users, roles never from the IdP.** First SSO login by a verified member of the bound org creates a `viewer`. Admins promote in the Users page. Local password login stays for break-glass admins | Satisfies T-2 in spirit (no passwords for NEXORA users) while keeping the "IdP cannot grant authority" rule from `docs/security.md`. A documented deviation from T-2 ("no local user table"): the table remains as a role projection | roles from Clerk org roles |
| D7 | **Claude pricing made true by mechanism, not by copy.** Pro = bring your own Anthropic key (it is already how `llm.api_key` works). Business/Enterprise = a monthly Tier 3 call budget counted in `llm_usage`; over budget falls back to the offline advisor | The pricing page promises "billed separately" and "budget included" with no code behind either | metering tokens and re-billing them (needs a billing product, not a feature) |
| D8 | **A downgrade never weakens enforcement.** Lapsed or lower plan: no new enrollments, advisor off, retention shrinks at next purge. Enrolled nodes keep enforcing their last bundle | Consistent with ADR-0006 (fail-open datapath, fail-closed control): a billing hiccup must not change what a firewall blocks | revoking over-quota nodes |
| D9 | **Events to Core go through an outbox**, counts and ids only. Built as: an in-memory queue persisted to the outbox table by a flusher within about 15 s, then retried (not written in the request transaction; a crash can lose the last seconds of counts, see `build-log.md`) | At-least-once with idempotency keys survives restarts and Core downtime for persisted events; Core never receives IPs, emails or flow data | fire-and-forget HTTP in the request path |
| D10 | **Notifications are signed webhooks only** (generic signed JSON; Slack and Teams incoming webhooks work through the `text` field; no PagerDuty or SIEM adapters). No SMTP in v1 | One mechanism, no deliverability problem to own | email |

## Stack

| layer | choice | why |
| --- | --- | --- |
| web | React 18 + Vite console served by the API | existing; 18 screens already |
| API | FastAPI (one process) | existing; OpenAPI at `/api/docs` |
| database | PostgreSQL 17 (prod), SQLite (single host) | existing; migrations must pass on both |
| ORM / migrations | SQLAlchemy 2 + Alembic (`0004`-`0006`) | existing |
| auth | Clerk (SSO via fragment token) + local argon2 for break-glass | existing; MFA is delegated to Clerk when SSO-only |
| payments | Stripe, owned by NEXORA Core in linked mode; NeuraWall's own Stripe code stays for standalone | D5 |
| email | none | D10 |
| jobs | in-process threads (`tier3-worker`, `maintenance`) + two new: `nexora-sync`, `outbox-flusher` | existing pattern; no queue dependency |
| files | none | |
| hosting | NEXORA OCI host, compose profile, `deploy.sh neurawall ...` (locking) | existing; never `docker compose` directly (memory note) |

## Schema

Tables: 12 existing + 4 new (`core_outbox`, `llm_usage`, `notification_channels`, `notification_deliveries`) + 2 altered (`users`: `external_id`, `auth_provider`; `subscriptions`: provider check).
Full DDL in `replica/schema.sql`. **Deviations from the skill's defaults, on purpose:** integer ids and epoch-float times instead of uuid and `timestamptz`, because the 12 existing tables and the SQLite path use them; changing conventions mid-schema costs more than it buys.
Money stays integer cents (`plans.py`). Foreign keys: `llm_usage.alert_id` -> `set null` (usage outlives the alert), `notification_deliveries.channel_id` -> `cascade`.
Access rules: **data-layer checks, no RLS.** One organisation per installation, so there is no tenant column; every route calls `authorize(role, Permission)` first. New permission: `MANAGE_INTEGRATIONS` (admin only), used by the link status/sync and notification routes.
Hard constraints: `users.external_id` unique (one NEXORA identity = one user); `core_outbox.event_id` unique and `notification_deliveries (channel_id, event_type, ref)` unique (dedupe at the database); `subscriptions.provider_subscription_id` unique (a sync is an upsert).

## API

New or changed routes (existing ones are in `docs/api.md`). Permission names are from `security/rbac.py`.

| method path | does | who | input | output | flow |
| --- | --- | --- | --- | --- | --- |
| `POST /auth/sso` (changed) | verify Clerk token; sign in; **create a `viewer` if `auth.sso_jit` and the org matches** | public, IP rate limit | `{token}` | session + user | F04, F07 |
| `GET /auth/sso/config` (changed) | adds `jit`, `local_login` so the console can hide the password form | public | - | `{enabled, login_url, jit, local_login}` | F04 |
| `GET /nexora/status` | linked?, org id, last sync, plan, error, outbox depth | `MANAGE_INTEGRATIONS` | - | status | F03 |
| `POST /nexora/sync` | pull the entitlement now | `MANAGE_INTEGRATIONS`, 6/hour | - | status | F03 |
| `GET /billing` (changed) | `source: "nexora"`, `manage_url` to the NEXORA console billing page | `READ` | - | adds `manage_url` | F03 |
| `POST /billing/checkout`, `/portal` (changed) | refuse with 403 when linked: "billing is managed in NEXORA" | `MANAGE_SETTINGS` | - | error | F03 |
| `GET /llm/usage` | calls this period vs the plan budget, by kind | `READ` | `period` (default current) | `{used, budget, period_start, period_end}` | F01 |
| `GET /notifications/channels` | list (secrets never returned) | `MANAGE_INTEGRATIONS` | - | channels | - |
| `POST /notifications/channels` | create; returns the signing secret once | `MANAGE_INTEGRATIONS` | name, url, events, min_severity | channel + secret | - |
| `PATCH /notifications/channels/{id}` | edit, pause, rotate secret | `MANAGE_INTEGRATIONS` | partial | channel | - |
| `DELETE /notifications/channels/{id}` | remove | `MANAGE_INTEGRATIONS` | - | 204 | - |
| `POST /notifications/channels/{id}/test` | send a sample event | `MANAGE_INTEGRATIONS`, 10/hour | - | delivery result | - |
| `GET /notifications/deliveries` | last 200 deliveries and status | `MANAGE_INTEGRATIONS` | `channel_id` | list | - |
| `GET /flows/export.csv`, `/alerts/export.csv` | stream CSV with the current filters, 50,000 row cap, spreadsheet-formula safe | `READ` | same filters as the list | text/csv | - |
| `GET /audit/export.csv` | same for the audit trail | `READ_AUDIT` | `from`, `to` | text/csv | F06 |
| `POST /auth/demo` | issue a `viewer` token; **exists only when `demo.public_login` and `demo_mode`** (separate demo instance) | public, 20/hour/IP | - | session | F07 |

Webhooks in: Stripe `/billing/webhook` unchanged (standalone only; ignored when linked). None new.
Webhooks out: notification channels, body `{event, ts, data}` signed `X-NeuraWall-Signature: sha256=HMAC(secret, "<ts>.<body>")`, the same `ts.body` scheme NEXORA already uses.
Calls out to Core (official, public, with the user's own org key): `GET api.onenexora.com/v1/entitlements/neurawall` and `POST api.onenexora.com/v1/events`.

Jobs:

| job | schedule | does |
| --- | --- | --- |
| `nexora-sync` | at start, then hourly with 0-5 min jitter | pull entitlement, upsert the `nexora` subscription row, write `settings['nexora.sync']`, audit on plan change |
| `outbox-flusher` | every 15 s while rows are due | send batches of up to 100 events, exponential backoff to 1 h, mark `sent_at`; also sends notification deliveries |
| `usage-rollup` | hourly | one event `neurawall.flows.ingested {count, nodes}` per hour, not per flow |
| purge (in `maintenance`) | existing loop | delete sent outbox rows after 7 days, `llm_usage` after the flow retention |

Events to Core (all counts and ids): `neurawall.alert.created {severity}`, `neurawall.rule.approved`, `neurawall.bundle.published {version}`, `neurawall.node.enrolled / revoked`, `neurawall.llm.call {kind, outcome}`, `neurawall.flows.ingested {count}`.

### What NEXORA must add (separate repo, live production: specified here, not built here)

| id | change in `../NEXORA` | note |
| --- | --- | --- |
| N1 | `GET /v1/entitlements/neurawall`, key scope `neurawall:link`, via `packages/api-kit` | returns `{org_id, plan_id, status, current_period_end}` from the org's `subscriptions` row |
| N2 | `POST /v1/events` batch, idempotent on `event_id` (new unique column on `audit_events` or a table), writes the usage feed | max 100 events per call; rejects unknown fields |
| N3 | add `neurawall` (community, pro, business, enterprise) to `packages/billing` plans; map the existing live Stripe prices (lookup keys `neurawall_<plan>_<interval>`) to Core subscriptions | **touches live Stripe**: needs your explicit go, and the old NeuraWall webhook must not also apply the same subscription |
| N4 | account `/sso/neurawall` token already carries `aud`; confirm the JWT template adds `email_verified` and `org_id` | D6 needs both |
| N5 | docs.onenexora.com entry for NeuraWall (T-8); registry copy changes from "not yet integrated" only when M1-M3 are live | do not claim it earlier |

## The parts that bite

- **JIT provisioning is the sharpest edge.** Rules: refuse JIT unless `sso_required_org_id` is set (otherwise any Clerk user would become a user); require `email_verified: true` in the token (today's code trusts Clerk's setting and never reads it); match by `external_id` first, then by email only for an existing user with no `external_id` (links once); never take a role from the token. Same generic 403 for every refusal, as today.
- **Deprovisioning lag.** Removing someone from the Clerk org stops *new* SSO logins but their session lives `access_token_ttl_seconds` (8 h). Linked users get a shorter `sso_session_ttl_seconds` (default 1 h); `sessions_valid_after` already allows a forced cut-off.
- **Fail-closed vs. availability (D8).** Core unreachable: keep the last entitlement for the 3-day grace, then Community. Community never revokes nodes. Test: unplug Core, advance the clock, confirm enforcement and bundles are unchanged.
- **Idempotency.** Outbox `event_id` is the key; Core must dedupe (N2). A webhook-style retry storm after Core downtime is bounded by batch size and backoff.
- **Races.** The LLM budget check and the `llm_usage` insert are not atomic, but there is exactly one `tier3-worker`, so overshoot is at most one call. If workers ever increase, move to `insert ... where (select count) < budget`.
- **Time.** Epoch UTC everywhere. The budget period is the subscription's `current_period_end` window when present, else the UTC calendar month; tested around month rollover and a 31-day month.
- **SSRF in webhooks.** A firewall console that POSTs to admin-supplied URLs is an SSRF primitive: https only, resolve and reject private/loopback/link-local ranges on save *and* at send time (pin the resolved IP), no redirects, 5 s timeout, 64 KB cap. The repo already had CodeQL path findings; run CodeQL on this.
- **CSV injection.** Cells starting with `= + - @` or tab/CR get a leading `'`. Row cap and streaming so an export cannot hold the process.
- **Secrets.** The NEXORA API key is configuration (`NEURAWALL_NEXORA__API_KEY`), never in the database; add it to the log redaction list. Webhook signing secrets are shown once. Where stored: reuse `security/credentials.py` if it supports reversible storage, otherwise keep only the hash and let the user rotate. Decide at build time; do not invent a new crypto scheme.
- **Data minimisation toward Core.** No IPs, emails, domains or flow fields leave the installation. Node ids are opaque.
- **GDPR deletion vs. the hash chain.** `audit_log.actor` holds an email, and the chain cannot be edited. Erasing a user would break `audit/verify`. Fix going forward: write `user:<id>` as the actor and keep email only in `users`; old rows stay and are documented. Needs an ADR.
- **Multi-tenancy:** not supported (D2). Two NEXORA orgs need two installations.
- **Rate limits:** SSO and demo share the IP limiter; sync 6/hour; test-send 10/hour.
- **Real-time, offline, search:** not affected. Console polling stays as is.
- **Single process (HA):** unchanged and deliberate; the new jobs are threads in the same process, so they stop with it. The outbox makes a restart lossless.

## Build order

Local build and tests only. Nothing is deployed, no live Stripe object is touched, the NEXORA repo is not edited.

1. **Vertical slice (M1): a NEXORA customer clicks "Open NeuraWall" and lands in the console.** Screens S01, S19, S21. Tables: `users` (+2 columns). Routes: `POST /auth/sso`, `GET /auth/sso/config`. Closes the "sign in works for a NEXORA customer" must. Tests: JIT happy path, no `org_id`, unverified email, role never from token, existing-user linking, deactivated user refused.
2. **Linked entitlements (M2), must.** S17, S18. Table: `subscriptions` (provider). Routes: `/nexora/status`, `/nexora/sync`, `/billing` changes. Job: `nexora-sync`. Client against a fake Core in tests. Tests: Core down, grace, downgrade keeps enforcement (D8), checkout refused when linked.
3. **Usage events (M3), should.** Tables: `core_outbox`. Job: `outbox-flusher`, `usage-rollup`. Tests: restart mid-flush, duplicate delivery, payload contains no IP or email.
4. **Claude plan mechanics (M4), must (pricing honesty).** S17, S18. Table: `llm_usage`. Routes: `/llm/usage`. Plan fields `llm_monthly_calls` (Community 0; Pro unlimited with BYOK; Business and Enterprise a number, see Decisions to confirm). Also **fix the pricing copy and the stale `docs/security.md` line** in the same change.
5. **Notifications and exports (M5), should/could.** S14-S16 plus a new Integrations page. Tables: `notification_channels`, `notification_deliveries`. Routes: notifications, CSV exports. Tests: SSRF block list, signature, CSV injection, row cap.
6. **Visitor demo (M6), should.** S01, S19. Route: `POST /auth/demo` on a separate demo instance with its own database, offline advisor, no keys. Screenshots for the product page come from it.
7. **Later (could):** standalone TOTP, HA design, multi-tenant (ADR-0009), SIEM-specific formats.

## Decisions to confirm (I proceed with the defaults unless you say otherwise)

1. Business/Enterprise monthly Tier 3 call budget. **Default: configurable, placeholder 3,000 and 15,000; not stated publicly until you set real numbers** (I have no Claude cost-per-call data, so I will not guess a margin).
2. Pro = bring your own Anthropic key (D7).
3. New SSO users start as `viewer`; no role mapping from Clerk (D6).
4. Core owns the subscription in linked mode (D5), which requires N3 in the NEXORA repo and a change to live Stripe wiring. That work waits for your explicit go.
