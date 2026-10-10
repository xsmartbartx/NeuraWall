# Build log: NeuraWall x NEXORA linked mode

Branch `feat/nexora-link` (from `fix/codeql-nul-byte-and-error-text`). Nothing committed, pushed or deployed. Date: 2026-10-10.
Gates at the end of the build: `ruff check`, `ruff format --check`, `mypy` (75 files), `lint-imports` (3 contracts kept), `pytest` all green, coverage 88% (CI floor 80), console `tsc` + `vite build` green, Alembic 0004-0007 verified up, down to 0003 and up again on SQLite.

| milestone / screen | state | what is missing | harder than expected |
| --- | --- | --- | --- |
| M1 S01 Login, S16 Users: JIT users, `local_login`, session TTL | done | needs `email_verified` in the Clerk JWT template and `NEURAWALL_AUTH__SSO_JIT=true` to take effect (N4) | found a real bug: `login()` and `login_sso()` expunged the user before flushing, so `last_login` was never saved and a linked identity would not have persisted. Fixed with a flush before expunge |
| M2 S17 Billing, S18 Settings: plan pull, org binding, no local checkout when linked | done | NEXORA side N1 (the `/v1/entitlements/neurawall` endpoint) does not exist yet; tested against a fake NEXORA | the Core-outage rule: a stale row could last forever, so a successful sync is valid 4 days (+3 days grace), then Community. Downgrade tested to leave 3 over-quota nodes enforcing |
| M3 usage events: queue, durable outbox, retries, hourly rollup | done | NEXORA side N2 (`/v1/events`, dedupe on `event_id`) | events are queued in memory and persisted by the flusher, not written in the request transaction, because a second SQLite writer inside `ingest` would block. A crash loses at most about 15 s of counts |
| M4 S17, S18: Claude metering, monthly budget, `/llm/usage` | done | budget numbers are placeholders (3,000 / 15,000); pricing page copy on the NEXORA site (N6) | the budget period is the UTC calendar month, not the subscription period (the pulled "period end" is a validity cap, not a billing period). Usage rows are kept 62 days, not "flow retention", or a 7-day retention would erase the month's count |
| M5 S23 Integrations (new), CSV exports on S04/S06/S15 | done | no email (by design), no syslog/CEF | SSRF-safe sender: resolve, check every address, pin the connection, keep the hostname for TLS. 40 unit tests incl. IPv4-mapped IPv6 and a name that turns internal after saving |
| M6 S01: "Try the demo" guest sign-in | done in code | the separate demo instance is not deployed; screenshots for the product page wait on it | the server refuses to start if it is enabled together with NEXORA linking, Stripe keys or a Claude key, because enabling a guest login on the real instance would be a data leak |
| Design pass: tokens, AA contrast | done | see `design/components.md` gaps | the console failed AA in 24 pairs (20 in the light theme) and its input borders were about 1.5:1. Fixed in the tokens |

## Known gaps carried forward (from `design/components.md`)

- Table rows that open a drawer are mouse-only (no keyboard access).
- Modals and drawers do not trap focus or return it to the trigger.
- Charts have no text alternative; the node-usage and Claude-usage meters have no `role="progressbar"`.
- `button` has no loading state beyond `disabled`.

## Not done, by decision

- Multi-tenancy (D2), SMTP (D10), TOTP for local accounts, HA, eBPF.
- Nothing touches `../NEXORA`. N1-N6 are specified in `architecture.md` and `docs/nexora.md` as the contract.
- PostgreSQL was not run locally (CI has a Postgres job); the migrations avoid dialect-specific SQL.
- The ChatGPT project chat was never read (login-gated).

## Deviations from `architecture.md`

| architecture said | built | why |
| --- | --- | --- |
| `GET /auth/sso/config` returns `password_login` | `local_login`, plus `demo` | a setting named `password_*` trips the repo's hardcoded-password lint (S105) |
| `notification_channels.secret_hash` | `secret_nonce`; the secret is derived from the server key | the server must sign, so it must know the secret; deriving avoids storing it |
| `notification_deliveries.status` includes `failed` | `pending | sent | dead` | a failed attempt is just a pending one with a later `next_try_at` |
| `llm_usage.alert_id`, kind/outcome incl. `timeout` | no `alert_id`; outcome `ok | refused | error` | the advisor hook does not know the alert; timeouts surface as `error` |
| `subscriptions.provider` check constraint | none | no value over the existing unique id; avoids a SQLite batch rebuild |
| usage retention follows flow retention | fixed 62 days | see M4 |
| budget period = subscription period | UTC calendar month | see M4 |
