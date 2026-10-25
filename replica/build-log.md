# Build log: NeuraWall x NEXORA linked mode

Branch `feat/nexora-link` (from `fix/codeql-nul-byte-and-error-text`). Date: 2026-10-10. **This is the state at the end of the first build; it is all merged and deployed since. See "State as of 2026-10-25" at the end.**
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

## State as of 2026-10-25

Everything is merged to `main` and deployed to the NEXORA host (92.5.69.99) at `7c78316`, through the locking `deploy.sh neurawall control-plane demo`.

**Live**
- Linked mode works (plan pull and usage events). The live instance is on **Community**: the Pro purchase was skipped, so the Claude advisor is offline.
- Product site at `neurawall.onenexora.com/` (generated by `scripts/build_site.py` into `neurawall/services/control_plane/site/`): `/`, `/pricing/`, `/security/`, `/docs/`, `/docs/detection/`, `/docs/evasion-report/`. The console is under `/app/`; old console URLs 308-redirect there. NEXORA's SSO handoff lands on `/#sso_token=...` and `site.js` forwards it to `/app/`. `tests/unit/test_site_in_sync.py` fails if committed pages differ from the generator.
- Public demo at `neurawall-demo.onenexora.com`: a separate instance (compose profile `demo`, container `neurawall-demo-1`, volume `neurawall_demodata`, `deploy.sh neurawall demo`), read-only guest login, synthetic traffic at `demo_flows_per_tick=6` with 6 h of retention. At the default rate it grew to 24 GB in six days, which is why those caps exist. DNS is at Squarespace; the edge route is in the NEXORA edge Caddyfile.
- NEXORA redirects `/products/neurawall` and `/products/vigilo` to the product sites.
- Clerk: the Production `neurawall-sso` JWT template carries `aud`, `email`, `org_id` and `email_verified`. JIT (`NEURAWALL_SSO_JIT`) is **off**; the new-user path has not been tested with a second NEXORA account.
- SonarCloud: 0 bugs; not a required check. A duplication exclusion for `neurawall/services/control_plane/site/**` is set in the SonarCloud UI.
- Bundle v3 is active at 100% and the node runs it.

**Owner-only, still open**
- Pro purchase, or leave Community.
- `gh auth refresh -h github.com -s workflow`: the assistant's token lacks that scope, so it cannot merge PRs that edit workflow files.
- The JIT test (turn `NEURAWALL_SSO_JIT=true` on, redeploy, sign in with a second account in a private window).
- Delete the last server backup `/opt/neurawall/.env.bak-demo-20261017T164237Z` when no longer needed (it holds secrets).

**Operating notes**
- Deploy only through `deploy.sh`. In the server `.env` the compose variable is `NEURAWALL_SSO_JIT`, not `NEURAWALL_AUTH__SSO_JIT`; a change to it needs a container recreate, which `deploy.sh` does when the environment changed.
- Re-run `uv run python scripts/build_site.py` after editing `docs/evasion-report.md`, `docs/encrypted-traffic.md` or the generator.
