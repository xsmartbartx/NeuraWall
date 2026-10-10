# Test plan: NeuraWall x NEXORA linked mode

Run 2026-10-10 against the local build only. Nothing was run against onenexora.com, NEXORA's API or Stripe.
**Result: 299 automated tests collected, all pass, 2 skipped (PostgreSQL: needs `NEURAWALL_TEST_DATABASE_URL`, CI has it). Coverage 88%.**
Browser click-through of the guest flow and the Integrations page done in the built-in browser. Playwright specs were **not written**: `npx playwright install` downloads a browser (about 150 MB) and I did not do that without your yes; the console has no e2e harness today.

Legend: A = automated (file), M = manual in the browser, - = not covered.

## F04 Sign in with NEXORA (JIT)  `tests/integration/test_sso.py`

| id | case | how |
| --- | --- | --- |
| F04-H1 | verified member of the organisation is created as a viewer, session 1 h, provisioning audited | A |
| F04-H2 | returning user matched by provider id even if the email changed | A |
| F04-H3 | existing user linked once by email | A |
| F04-E1 | role claims in the token (`role`, `org_role`, nested) never grant a role | A |
| F04-E2 | `email_verified` false, string `"true"`, missing | A |
| F04-E3 | no organisation, wrong organisation | A |
| F04-E4 | overlong subject (65 chars) and overlong email (260 chars) refused, not truncated or a 500 | A (bugs B1, B3) |
| F04-E5 | two tabs finish the first sign-in at once: unique collision becomes a refusal, retry works | A (B2) |
| F04-E6 | an email already linked to a different identity is refused | A |
| F04-N1 | deactivated user, expired token, wrong issuer, wrong key, garbage | A |
| F04-N2 | JIT user has no password; admin password reset refused | A |
| F04-N3 | `local_login=admin_only`: non-admin password sign-in refused with the same error as a wrong password | A |
| F04-N4 | `sso_jit` without a JWKS URL or an organisation fails at startup | A |
| F04-X1 | real Clerk tokens (claim names, `email_verified` in the JWT template) | **- needs the real Clerk instance (N4)** |

## F03 Plan and billing (linked)  `test_nexora_link.py`, `test_billing_api.py`

| id | case | how |
| --- | --- | --- |
| F03-H1 | sync applies the plan, key sent as a bearer token, audited on change | A |
| F03-H2 | checkout and portal refused when linked; Stripe webhook ignored; a stale Stripe row cannot compete | A |
| F03-E1 | NEXORA down: plan kept, then lapses after 4 days + 3 days grace (clock moved) | A |
| F03-E2 | period end from NEXORA caps validity | A |
| F03-E3 | **downgrade with 3 enrolled nodes on a 1-node plan: all nodes keep fetching bundles, heartbeating and sending flows; a new enrollment is refused** | A |
| F03-N1 | key for a different organisation, 401/403/500, unreadable answer | A |
| F03-N2 | manual sync rate-limited at 6 per hour; non-admin forbidden; the key never appears in any response | A |
| F03-N3 | standalone installs unchanged | A |

## F01 Claude plan mechanics  `test_llm_budget.py`

Budget reached then offline advisor (A); budget resets with the UTC month, incl. Dec to Jan and 29 Feb (A); Pro uncapped and counted (A); Community never reaches the model (A); refusals counted, errors not (A); a metering failure never breaks triage (A); old rows purged, this month's kept (A).

## Usage events  `test_nexora_events.py`

Delivered once with the key (A); **no IP, email, node name or key in any payload** (A); failed send retried with the same event id after backoff (A); survives a restart (A); batches of 100 (A); rejected key backs off without touching the plan (A); can be switched off (A); hourly rollup counts only (A); purge and bound (A).

## Notifications  `test_webhook.py` (47), `test_notifications.py`

SSRF: 14 internal address classes, a name with one internal answer among public ones, a name that turns internal after saving (never contacted), numeric/hex/octal/short IP spellings and `localhost.` with the real resolver (A). Signing, rotation, derived secret not stored, pinned connection with the real hostname for TLS, redirects not followed, non-2xx, timeouts (A). Once per event per channel, severity and event filters, pause, retries to "dead", deletion cascades, permissions, unicode and blank names (A). URL secret never in API, audit or logs (A).

## Exports  `test_export.py`

Formula cells (`= + - @ tab CR`), row cap, filter parity with the list, hostile hostname, permissions, audit of the export itself (A).

## F07 Visitor demo  `test_demo_login.py` + browser

Off by default (A). Guest is a viewer for 30 min; 7 privileged endpoints return 403 (A, M). Rate limit 20/h (A). Cannot be enabled with NEXORA linking, Stripe keys or a Claude key (A). Admin changing the demo account disables it (A).
**Manual (M)**: "Try the demo" button signs in; sidebar hides Users, Audit and Integrations; 8 console pages render with no error callout; CSV export works; Integrations page renders at 375 px with no horizontal scroll; an internal URL is refused with the server's message in the dialog.

## Not covered

- Real NEXORA and Clerk (N1, N2, N4 do not exist yet).
- Stripe test cards and live Stripe: not touched.
- Email: not a feature.
- Keyboard-only and screen-reader pass of the new Integrations page, and an axe scan: **not done** (needs the e2e harness). Known gaps are in `design/components.md`.
- Two tabs, slow network, offline in the console: not exercised.
- PostgreSQL and the CI-only jobs.
