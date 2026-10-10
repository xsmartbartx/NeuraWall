# Linking NeuraWall to NEXORA

Linked mode is optional and off by default. A standalone installation (a licence plan, or its own
Stripe subscription) works exactly as before. Linking ties **one installation to one NEXORA
organisation**: NeuraWall serves a single organisation per control plane, so two organisations need
two installations.

| What | Standalone | Linked |
|---|---|---|
| Sign-in | Passwords, optional "Sign in with NEXORA" for existing users | Same, plus just-in-time viewers ([Security](security.md#just-in-time-users)) |
| Plan and limits | Licence (`billing.plan`) or the installation's own Stripe subscription | Pulled from NEXORA. Local checkout and the Stripe webhook are switched off |
| Usage | Stays on the host | Counts (no addresses or emails) are sent to the NEXORA usage feed |

## Turning it on

```bash
NEURAWALL_NEXORA__API_KEY=nx_live_...            # an organisation key with the neurawall:link scope
NEURAWALL_AUTH__SSO_JWKS_URL=https://clerk.example.com/.well-known/jwks.json
NEURAWALL_AUTH__SSO_REQUIRED_ORG_ID=org_...      # binds this installation to the organisation
```

Settings are in [configuration.md](configuration.md#nexora). Setting `NEURAWALL_AUTH__SSO_REQUIRED_ORG_ID`
also makes the plan pull refuse an API key that belongs to a different organisation.

The console shows the link on **Integrations** (admins): organisation, plan, last sync, how many
events are waiting to be sent, and a **Sync now** button (six presses per hour).

## What happens when NEXORA is unreachable

* The control plane only ever calls out. It never needs an inbound connection from NEXORA.
* A successful sync keeps the plan valid for four days, plus the usual three days of billing grace.
  After that, with no successful sync, the installation falls back to the Community plan.
* **A plan change never changes what the firewall enforces.** Enrolled nodes keep their last signed
  bundle and keep sending flows. A downgrade only stops *new* nodes being enrolled, turns the Claude
  advisor off where the plan has none, and shortens flow retention at the next purge.
* Usage events are queued in memory and written to a database outbox within about 15 seconds. From there they survive restarts and are retried with backoff (up to an hour apart, at most 50,000 kept). Events still in memory when the process crashes are lost, so counts can be short by a few seconds' worth.

## What is sent to NEXORA

Event types: `neurawall.alert.created {severity}`, `neurawall.rule.approved {mode}`,
`neurawall.bundle.published {version, rules}`, `neurawall.bundle.rolled_back {version}`,
`neurawall.node.enrolled`, `neurawall.node.revoked`, `neurawall.llm.call {kind, outcome}`,
`neurawall.flows.ingested {count}` (once an hour). Never an IP address, domain, email, node name,
flow field or alert text. Turn it off with `NEURAWALL_NEXORA__EVENTS_ENABLED=false`.

## The contract NEXORA has to serve

Both calls carry `Authorization: Bearer <api key>`; redirects are never followed.

`GET {api_url}/v1/entitlements/neurawall`

```json
{"org_id": "org_...", "plan_id": "pro", "current_period_end": 1793000000}
```

`plan_id` is the plan NEXORA has already resolved (`community`, `pro`, `business` or `enterprise`; a
lapsed or unpaid subscription arrives as `community`). `current_period_end` (epoch seconds, or `null`)
caps how long the plan stays valid.

`POST {api_url}/v1/events`

```json
{"events": [{"event_id": "uuid", "type": "neurawall.alert.created", "ts": 1793000000.2, "data": {"severity": "high"}}]}
```

Up to 100 events per call. Answer 2xx once they are stored. `event_id` is the idempotency key: a retry
after a timeout sends the same ids.

## Claude and the plans

| Plan | Claude | Meter |
|---|---|---|
| Community | Offline advisor only | none |
| Pro | Your own Anthropic key (`ANTHROPIC_API_KEY`), billed by Anthropic | calls are counted, never capped |
| Business, Enterprise | A monthly call budget included (`billing.llm_calls_business`, `billing.llm_calls_enterprise`) | counted per UTC month; over budget the offline advisor answers until the month ends |
| Enterprise Dedicated | Your own key | counted |

The defaults (3,000 and 15,000 calls a month) are placeholders until the plan limits are decided.
`GET /api/v1/llm/usage` and the Billing page show the month's use. Only the call count, kind, model and
token totals are stored, never the prompt or the answer.
