# Backend: NeuraWall x NEXORA linked mode

The product is a backend, so this is the checklist applied to what was built. No service accounts were created and no key was typed: the NEXORA API key and Stripe keys are environment variables the owner sets.
`.env.example` equivalent: `deploy/compose/nexora-host.env.example` (names only, no values; the new variables are at the end). The generated `docs/configuration.md` lists every setting.

## Auth

| item | state |
| --- | --- |
| Email sign-up and verification | n/a: NeuraWall users are created by an admin or by SSO; verification is Clerk's, and JIT refuses unless the token says `email_verified: true` |
| Password reset | admin reset exists; refused for SSO-provisioned accounts (no password) |
| OAuth | via NEXORA's Clerk (Google lives there); NeuraWall only verifies the Clerk token (RS256, issuer, audience, organisation) |
| Sessions | bearer JWT held in `sessionStorage`, 8 h (SSO: 1 h with JIT); revocation through `sessions_valid_after`. Not cookies, a deliberate existing design |
| Roles | viewer, analyst, operator, approver, admin; one `authorize(role, permission)`; new permission `integrations:manage` (admin) |
| Account deletion | **gap**: users can be deactivated, not erased, because `audit_log.actor` holds the email and the hash chain cannot be edited. Fix: log `user:<id>` as the actor going forward, an ADR is needed |

## Database

- Migrations 0004 (SSO identity), 0005 (`llm_usage`), 0006 (`core_outbox`), 0007 (notifications): checked in, run at startup, verified up/down/up on SQLite. **PostgreSQL not run locally** (the CI Postgres job covers it).
- Access rules: no tenant column (one organisation per installation), data-layer `authorize()` on every route. Tested with a second, lower-privileged user for exports, notifications, NEXORA status, audit export and the demo guest (all 403).
- Seed: `demo_mode` generates synthetic traffic only; no real people.
- Backups: server-side nightly job covers the `neurawall-postgres` container and the control-plane volume (from the deploy notes). Not verified in this session.

## Payments

- Linked mode: NEXORA owns the subscription; NeuraWall's own Checkout/Portal return 403 and its Stripe webhook answers `ignored`, so the two cannot compete.
- Standalone mode: unchanged (verified signature, only this installation's subscriptions, idempotent upsert on the subscription id, 3-day renewal grace).
- Cancelling: in the NEXORA console (one place). **Not tested end to end**: needs N1 and N3 on the NEXORA side and live Stripe, which I did not touch.
- Webhook events the skill lists: `checkout.session.completed` and `invoice.payment_failed` are not handled in standalone mode (status comes from `customer.subscription.*` and `past_due` keeps access). Noted, not changed.

## Email and jobs

- Email: none (decision D10): webhooks instead.
- Jobs (threads in the one process): `tier3-worker`, `maintenance` (30 s: retention, outbox/delivery purge), `notify` (5 s: queue, retries with backoff, dead after 6), `nexora-sync` (hourly + jitter), `outbox` (15 s). All UTC. Failures are logged and retried; "dead" deliveries stay visible in the console.

## Integrations

| integration | API | scope / review | notes |
| --- | --- | --- | --- |
| NEXORA Core | `GET /v1/entitlements/neurawall`, `POST /v1/events` (to be built on the NEXORA side, contract in `docs/nexora.md`) | org API key, `neurawall:link` | no inbound connection; redirects never followed; 64 KB response cap |
| Clerk | JWKS verification only | JWT template must add `email_verified`, `org_id`, `aud` | no Clerk secret key is used or stored |
| Anthropic | official SDK, own key (Pro) | none | usage metered per UTC month |
| Customer webhooks (Slack, Teams, PagerDuty, SIEM) | their incoming-webhook URLs | none | SSRF-safe, signed |

## Security checklist

- [x] secrets only in env vars; `.env` ignored; the NEXORA key is a `SecretStr`, never returned (tested on `/nexora/status`, `/billing`, `/system`); new redaction for `nx_live_`, `nwk_`, `nwe_`, `whsec_` in logs
- [x] input validated on the server on every new route (pydantic models with length and enum limits, https-only webhook URLs)
- [x] authorisation checked on every read and write, tested with a lower role (403)
- [x] rate limits: demo 20/h/IP, SSO shares the login limiter, manual NEXORA sync 6/h, webhook test 10/h
- [x] webhooks (inbound Stripe) verify signatures; outbound webhooks are signed
- [x] uploads: none exist
- [x] no user data in URLs or logs: audit detail records only the webhook host; events to NEXORA carry counts only (tested: no IP, email, node name or key in any payload); Slack-style secret URLs are never returned by the API
- [~] dependencies: `npm audit` 0 vulnerabilities; **`pip-audit` could not run locally** (uvx failed to create its environment), CI runs it
- [ ] privacy policy lists every processor: lives on the NEXORA site (marked draft); NeuraWall adds none by default, Anthropic only when a key is set

## Open items for the owner

1. NEXORA side N1-N6 (`architecture.md`) before linked mode can run for real.
2. Privacy policy and terms are drafts without a legal entity.
3. Account erasure vs. the audit hash chain (above).
4. Real Claude call budgets and the pricing page wording.
