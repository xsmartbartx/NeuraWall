# Recon map: NeuraWall (web console + control-plane API, NEXORA tenant)

Subject: NeuraWall itself (own product, own repo, live at neurawall.onenexora.com). This is a **self-audit**, not a clone:
the "original" is what NEXORA promises publicly and what the platform expects of a tenant; the "clone" column is what the
repo does today. The map doubles as a gap analysis. Sibling map for the platform: `../NEXORA/replica/recon.md`.
Slice: the core loop below, plus the NEXORA integration seam (identity, entitlements, usage, billing).
For: security teams (SMB to mid-market) who want an AI-assisted firewall they can trust to not silently drop traffic.
Date: 2026-10-10. Version audited: 1.1.0 (live `/api/v1/version` = 1.1.0), branch `fix/codeql-nul-byte-and-error-text`.

## Sources

| # | source | URL / path | notes |
| --- | --- | --- | --- |
| 1 | repo | this repo (README, CHANGELOG, `docs/*`, `neurawall/`, `console/src/`, `tests/`) | read; 131 test functions, 8 ADRs |
| 2 | marketing site | https://onenexora.com | fetched: positioning "Build. Secure. Operate."; NeuraWall listed as Beta |
| 3 | product page | https://onenexora.com/products/neurawall | fetched: states "not yet integrated with NEXORA's Core identity and entitlements"; no screenshots |
| 4 | pricing | https://onenexora.com/pricing | fetched: NeuraWall 5 tiers (see Pricing check) |
| 5 | docs | https://docs.onenexora.com | fetched: Quickstart only (`GET /v1/products`); NeuraWall = a name in a list |
| 6 | live instance | https://neurawall.onenexora.com | `/healthz` 200, `/api/v1/version` 1.1.0, `/api/v1/auth/sso/config` enabled. Own site, public endpoints only. Not logged in. |
| 7 | sibling repo | `../NEXORA` (`README.md`, `replica/*`) | read: platform already ran this pipeline; NeuraWall is listed there as an external tenant (S25, F06) |
| 8 | memory | deploy notes (server, Stripe ids, Claude key setup) | read; ids stay out of this file |
| 9 | ChatGPT project chat (`chatgpt.com/g/g-p-6abe9723.../c/6ac1dbff-...`) | pasted by the user | **not retrievable**: it sits behind the user's ChatGPT login and I do not sign into accounts. Paste or export the text into `replica/sources/` and I will fold it in. |

## Core loop

An analyst sees an alert, Claude drafts a narrowly scoped alert-only rule, a human simulates its blast radius and approves it, and a signed bundle
rolls out 5% -> 25% -> 100% to nodes that enforce it, with automatic rollback. (The promise: a model proposes, a policy engine decides, a human approves.)

## Screens

Console routes are from `console/src/main.tsx`. Public pages are the NEXORA surfaces that lead into it.

| ID | screen | route / how to reach | purpose | key components | states seen (code) |
| --- | --- | --- | --- | --- | --- |
| S01 | Login | `/` when signed out | password login, "Sign in with NEXORA" | form, SSO button, error text | idle, wrong password, rate-limited (429), SSO refused (generic 403), SSO off (no button) |
| S02 | Force password change | `/` when `must_change_password` | first-login / reset flow | form | validation error |
| S03 | Overview | `/` | verdicts over time, detections by label, open alerts, top flagged sources | PageHead, Card, charts, hours selector | loading, error, empty (no traffic) |
| S04 | Alerts | `/alerts` | grouped suspicious flows, severity, status | table, filters, AI badge | loading, empty, filled |
| S05 | Alert detail | `/alerts/:alertId` (drawer) | summary, flows, Claude narrative, triage, status/assignee | Drawer, Badge, narrative card | Claude vs heuristic vs offline source; no narrative yet |
| S06 | Flow explorer | `/flows` | every analysed flow, filters (`q`, action, label, node, min score) | table, filters | empty, filled |
| S07 | Flow detail | drawer from S06 | Tier 1 anomaly, Tier 2 labels, verdict, "explain" | Drawer, Card x3 | explanation pending / done |
| S08 | Approvals | `/approvals` | pending rule drafts | table, tabs by status | empty, pending, decided |
| S09 | Draft detail | `/approvals/:draftId` (drawer) | simulation, blast radius, approve (mode + note) / reject (reason) | Drawer, Modal | over blast threshold (ack required), four-eyes refusal, already decided |
| S10 | New draft | modal in S08 | author a rule | Modal, form | validation error |
| S11 | Rules | `/rules` | approved rule set, priority order, hygiene findings | table, hygiene dot | empty, filled, hygiene finding |
| S12 | Rule detail | drawer from S11 | edit/disable/delete | Drawer, Modal (delete) | confirm delete |
| S13 | Bundles & rollout | `/bundles` | signed bundle versions, stage, advance, roll back | table, Modal (rollback) | rolling_out, active, rolled_back |
| S14 | Fleet | `/fleet` | nodes, version applied, backend, datapath error; enroll, revoke | table, Modal x2 | none enrolled, stale, datapath error, plan quota reached |
| S15 | Audit | `/audit` | hash-chained trail, verify | table | verify ok / chain broken |
| S16 | Users | `/users` | RBAC, add user, temp password, reset | table, Modal x2, roles card | filled |
| S17 | Billing | `/billing` | plan, node meter, retention, plans grid, Stripe checkout/portal | Meter, Badge, callout | no subscription (Community), active, past_due, self-serve off, `?checkout=success` |
| S18 | Settings | `/settings` | system status, Tier 3 advisor status, signing key, own account | Cards | advisor degraded / offline |
| S19 | NeuraWall product page | onenexora.com/products/neurawall | positioning, "Open NeuraWall" | marketing | Beta badge |
| S20 | Pricing (NeuraWall block) | onenexora.com/pricing | 5 tiers | table | monthly / yearly |
| S21 | SSO bridge | account.onenexora.com/sso/neurawall | Clerk session -> short-lived token -> console fragment | (NEXORA repo) | refused: no matching NeuraWall user |
| S22 | API docs | `/api/docs`, `/api/openapi.json` | OpenAPI | FastAPI Swagger | - |

## Flows

```
F01 Alert to enforced rule  (the core loop)
    S04 alerts -> S05 alert (Tier 3 triage -> draft) -> S09 draft (simulate, blast radius) -> approve
    -> S13 bundle v(N+1) 5% -> 25% -> 100% -> S11 rule active
    happy path clicks: 5 (open alert, triage, open draft, approve, confirm); canary then advances on its own
    edge: blast radius over 1% needs ack; four-eyes (author may not approve); canary block-rate regression -> auto-rollback;
          Claude budget spent or plan has no advisor -> offline heuristic draft; identical pending draft is reused

F02 Enroll a node
    S14 fleet -> create enrollment token (modal) -> agent POST /agent/enroll -> node appears -> heartbeat -> bundle applied
    happy path clicks: 3 (+ run the agent command on the host)
    edge: token expired / used; plan node limit reached (upgrade prompt); node revoked

F03 Upgrade the plan
    S17 billing -> Upgrade to Pro/Business/Enterprise -> Stripe Checkout -> ?checkout=success -> webhook -> plan applied
    happy path clicks: 2 (+ Stripe form)
    edge: self-serve off -> contact sales; webhook delay; lapsed -> 3-day grace then Community; Dedicated by licence only

F04 Sign in with NEXORA (SSO)
    S01 -> S21 account.onenexora.com/sso/neurawall -> fragment token + state -> POST /auth/sso -> S03
    happy path clicks: 1 (if already signed in at NEXORA)
    edge: no matching active NeuraWall user -> generic 403 (live today for any non-seeded email); state mismatch -> discarded; wrong audience

F05 Roll back a bundle
    S13 -> Roll back v(N) -> confirm -> new higher version with previous rules (never an old bundle)

F06 Verify the audit trail
    S15 -> verify -> chain ok / first broken seq

F07 Visitor to first alert  (documented, partly manual)
    S19/S20 -> "Open NeuraWall" -> S01 -> (no self-signup) -> operator-created account or SSO
    happy path: not completable by a stranger today: there is no sign-up, trial or demo link on the public pages
    (quickstart compose + `demo_mode` exist, but are self-host paths)
```

## Components

| component | variants | states | used on |
| --- | --- | --- | --- |
| PageHead | title, description, actions | - | all pages |
| Card | padded / flush, titled, actions | - | all |
| Badge | active, revoked, ai, severity/status kinds | - | S04-S18 |
| Drawer | titled, sub-line | open, loading | S05, S07, S09, S12 |
| Modal | footer actions | open, busy, error | S10, S12, S13, S14, S16 |
| Table | truncate, mono, sortable none | loading, empty (`Empty`), filled | S03-S16 |
| Meter | warn on 100% | normal, warn | S17 |
| Charts (`charts.tsx`) | verdicts over time, labels | empty, filled | S03 |
| Loading / ErrorBox / Empty | - | - | all |
| Toast | success, error | - | all |
| Layout / nav | sidebar + mobile menu (hamburger), counts, hot badge | collapsed, open | all |
| Theme | dark (default), light via `localStorage` | - | all |

## Inferred data model

Read from `neurawall/services/control_plane/db.py` (SQLAlchemy), so confidence is high unless marked.

```
User            id, email, name, role (viewer|analyst|operator|approver|admin), password_hash, active, must_change_password,
                sessions_valid_after, last_login                              evidence: db.py, S16   confidence: high
Node            id, name, api_key_hash, hostname, agent_version, backend, applied_version, enrolled_at, last_seen, revoked, stats(json)
EnrollmentToken id, token_hash, created_by, expires_at, uses_remaining, used_by_node
Rule            id(8), data(json), deleted, updated_at
RuleDraft       id, data(json), status, created_by, decided_by, decision_note, rule_id, alert_id
Bundle          version, envelope(json, Ed25519-signed), rule_count, stage_index, status, note
Flow            flow_id, node_id, ts, src_ip, dst_ip, dst_port, protocol, action, enforced, rule_id, anomaly_score, labels,
                flow/signals/verdict(json), alert_id        (metadata only; payloads never stored)
Alert           id, group_key, status, severity, title, summary(+source), labels, src/dst, counts, max_score, assignee,
                recommended_actions, narrative(json), draft_id, tier3_pending
AuditEntry      seq, ts, actor, action, target, detail, prev_hash, hash   (hash chain)
Subscription    provider, provider_subscription_id, provider_customer_id, plan_id, status, current_period_end
NodeStat        node_id -> Node, ts, applied_version, blocked, flows
Setting         key, value(json)
```

Relationships: Node 1-n Flow; Alert 1-n Flow; Alert 0-1 RuleDraft; RuleDraft 0-1 Rule; Rule n-1 Bundle (compiled in); Node n-1 Bundle (applied_version);
Subscription 1 per installation.

**Seam to NEXORA (the gap):** NeuraWall has no `Organisation`. One control plane = one organisation (`plans.py` says so). NEXORA keys plans,
API keys, usage and audit by `orgId` in its own Postgres; NeuraWall keeps its own `User` table and its own Stripe subscription.
`User.email` is the only link (SSO maps a Clerk email to an existing user). confidence: high (code), medium (what the Core contract wants: see NEXORA architecture doc).

## Pricing check (public page vs `modules/billing/plans.py`)

| plan | public (onenexora.com/pricing) | code | match |
| --- | --- | --- | --- |
| Community | $0, 1 node, 7 d, offline advisor | 1 node, 7 d, advisor off | yes |
| Pro | $149 / $1,490, 5 nodes, 7 d, "Optional Claude AI (billed separately)" | same prices; advisor **allowed**, no separate billing or metering | **no: claim has no mechanism** |
| Business | $499 / $4,990, 25 nodes, 30 d, "Claude AI usage budget included" | same; only the global hourly cap (`llm.max_calls_per_hour`), no per-org or per-plan budget | **no: "included budget" is not metered** |
| Enterprise | $3,000 / $30,000, 100 nodes, 90 d | same | yes |
| Enterprise Dedicated | $5,000-15,000, custom | $5,000 list, not self-serve | yes |

## Feature matrix

See `features.csv`. In this self-audit the `original` column means "promised publicly or required of a NEXORA tenant" and `clone` is the
verified state in this repo (`yes` / `partial` / `no` / `skip`), not a build counter.

## Out of scope (cannot or should not be built here)

- The NEXORA network of products and users (Sentinel, CSPM, Gateway, Vigilo) - separate repos, not part of this slice.
- Hardware / kernel work: eBPF/XDP datapath is a deliberate later backend (ADR-0002); nftables is the shipped one.
- TLS interception (ADR-0004: rejected on purpose).
- Threat-intel feeds and commercial rule packs (licensed content); GeoLite2 is mounted from the host, under MaxMind's licence.
- Regulated certifications (SOC 2, ISO 27001): process and audit, not code.
- Legal text: NEXORA's Terms/Privacy are marked draft with no reviewed entity.

## Size

Screens 22 (18 in the console), flows 7, entities 12. Hard parts: (1) **Core integration**: org model, entitlements and usage events from NEXORA,
without breaking self-hosted installs; (2) **LLM cost control**: per-org metering behind "budget included" / "billed separately";
(3) **single-process control plane**: state in memory (baselines, Tier 3 queue, rate limits), so HA needs a design, not a flag.
Size of the *integration slice*: **M** (a few weeks). The product itself is already built (1.1.0 live).

## Findings to carry into /replica-architect

1. Pro/Business Claude claims on the pricing page have no code behind them (table above).
2. `docs/security.md` line 109 is stale: it says "The console has no SSO button yet"; the button shipped in 6e33356.
3. SSO is live but only works for emails that already exist as NeuraWall users, so a NEXORA customer clicking "Open NeuraWall" is refused. Needs a provisioning decision (JIT user from a verified NEXORA org membership vs. invite-only).
4. No MFA/TOTP, email/SMTP, webhooks out (Slack, PagerDuty, syslog/SIEM), or CSV export in the code. Likely table stakes for a firewall console; priority to be set after the chat and review steps.
5. Public pages have no screenshots of the console and no sign-up/demo path for a visitor (F07).
6. The ChatGPT project chat is unread (login-gated).
