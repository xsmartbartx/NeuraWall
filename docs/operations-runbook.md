# Operations runbook

## Health and monitoring

| Endpoint | Purpose |
|---|---|
| `GET /healthz` | Liveness (process up) |
| `GET /readyz` | Readiness (database reachable, bundle available) |
| `GET /metrics` | Prometheus metrics |

Key metrics:

| Metric | Watch for |
|---|---|
| `neurawall_flows_ingested_total{node}` | A node's rate dropping to zero: sensor or agent down |
| `neurawall_verdicts_total{action,enforced}` | Sudden rise in `enforced="true"`: a new rule over-blocking |
| `neurawall_ingest_malformed_total` | Sensor emitting bad records |
| `neurawall_tier2_rate_limited_total` | Tier 2 shedding load; raise `inference.t2_rate_per_second` or add CPU |
| `neurawall_tier3_calls_total{source,outcome}` | `outcome="error"` or `"budget_exhausted"`: Tier 3 degraded |
| `neurawall_datapath_bundle_applies_total{result="error"}` | nftables failing on a node |
| `neurawall_http_request_seconds` | API latency |

The **Fleet** page shows each node's applied bundle, last heartbeat, active blocks and
datapath errors. A node is *offline* after 2 minutes without a heartbeat.

## Backup and restore

What to back up:

1. **PostgreSQL** database (rules, bundles, alerts, flows, audit trail, users).
2. **Data directory** (`/data` in containers): `keys/bundle-signing.pem` is the root of trust
   for every node. Losing it means re-enrolling all nodes. Leaking it lets an attacker sign
   policy.

```bash
docker compose exec -T postgres pg_dump -U neurawall -Fc neurawall > neurawall-$(date +%F).dump
docker compose cp control-plane:/data/keys ./keys-backup && chmod -R go-rwx ./keys-backup
```

Restore: stop the control plane, restore the database (`pg_restore --clean`) and the `keys`
directory, then start the control plane. Verify with `neurawall verify-audit`.

## Audit trail

Every approval, rule change, bundle publish, rollback, enrollment, sign-in and user change is
appended to a SHA-256 hash chain. Verify it any time:

```bash
docker compose exec control-plane neurawall verify-audit
```

or use **Audit trail → Verify chain integrity**. A failure names the first altered or missing
entry. Treat it as a security incident: restore from backup and investigate database access.

## Common procedures

**A new rule is blocking legitimate traffic.**
Bundles → **Roll back** the bundle that introduced it. This publishes the previous rule set as a
new version immediately to all nodes. Then disable or narrow the rule and re-approve it.
Automatic rollback also triggers during canary stages when canary nodes block ≥ 2 percentage
points more traffic than the rest (`policy.rollback_block_rate_increase`).

**A host is noisy during a planned change (deployment, backup window).**
Create an `allow` rule scoped to the host, with a lower priority number than the rules it
should override, and disable it after the window. (Tier 1 change-window suppression exists in the
engine API, `AnomalyEngine.suppress`, but is not yet exposed in the console.)

**Tier 3 shows *degraded*.**
Settings → Tier 3 advisor shows the last error. Typical causes: invalid or rotated API key,
network egress blocked to `api.anthropic.com`, or the hourly budget exhausted
(`llm.max_calls_per_hour`). Workflows continue with the offline advisor meanwhile.

**Rotate the session secret.** Change `auth.secret_key` and restart. Everyone is signed out.

**Revoke a node.** Fleet → **Revoke**. Its API key stops working at once. It keeps enforcing
its last bundle until you stop it or re-enroll it with a new token.

**Rotate the bundle-signing key** (e.g. after suspected exposure):

1. Stop the control plane and move `keys/bundle-signing.pem` away. At next start a new key is
   generated and the current rule set is re-signed and published as a new bundle version.
2. Re-enroll every node (delete `/var/lib/neurawall-agent/agent-state.json`, run
   `neurawall agent enroll` with a new token). Nodes will reject bundles signed by the new
   key until re-enrolled. This is intended.

**Locked out of the last admin account.**

```bash
docker compose exec control-plane neurawall create-user --email you@example.com --role admin
```

## Incident response with NeuraWall

1. **Alerts** → open the alert. Read the summary and recommended actions, then run
   **Narrate incident** for a timeline.
2. **Flow explorer** → filter by the source IP. Open flows to see which tier flagged what and why
   (feature attributions); use **Explain this verdict** for a plain-language account.
3. **Approvals** → review the drafted containment rule and its blast radius, and approve it in
   enforce mode with a note.
4. After containment, mark the alert *resolved* (or *false positive*, which is recorded for
   tuning).

## Data retention

Flow records are purged after the plan's retention (Community/Pro 7 days, Business 30,
Enterprise 90; `flow_retention_seconds` overrides it); they back the
simulator and investigations. Node heartbeats are kept 7 days. Alerts, rules, bundles, drafts
and the audit trail are kept indefinitely. Export them before deleting data for compliance.

## Billing (Stripe)

Plans: Community (free, 1 node, 7-day retention, offline advisor), Pro, Business and Enterprise
(self-serve via Stripe), Enterprise Dedicated (licence via sales). An active Stripe subscription
sets the plan. Otherwise `billing.plan` does, which is how licensed self-hosted installs are configured.
Unknown or lapsed plans fall back to Community.

To enable self-serve billing on an installation:

1. In Stripe, create one Product per paid plan with a monthly and a yearly recurring Price
   (Pro $149/$1,490, Business $499/$4,990, Enterprise $3,000/$30,000).
2. Add a webhook endpoint `https://<public_url>/api/v1/billing/webhook` for
   `customer.subscription.created`, `.updated` and `.deleted`; copy its signing secret.
3. Set `NEURAWALL_BILLING__STRIPE_SECRET_KEY`, `NEURAWALL_BILLING__STRIPE_WEBHOOK_SECRET` and the six
   `NEURAWALL_BILLING__PRICE_<PLAN>_<MONTH|YEAR>` ids, then restart.

The Stripe account may be shared with other products: NeuraWall tags its subscriptions with
`metadata.neurawall_installation` and ignores every other event (200 "ignored"), so it never
applies, or breaks, another product's billing. Plan changes are recorded in the audit trail
(`billing.*`).
