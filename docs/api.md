# API

Interactive OpenAPI documentation is served by every control plane at **`/api/docs`**
(schema at `/api/openapi.json`). All endpoints are under `/api/v1`.

## Authentication

**Users**: exchange credentials for a bearer token:

```bash
TOKEN=$(curl -s https://nw.example.com/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"you@example.com","password":"…"}' | jq -r .access_token)
curl -s https://nw.example.com/api/v1/alerts?status=open -H "Authorization: Bearer $TOKEN"
```

**Nodes**: use the `nwk_…` API key returned by enrollment as a bearer token on
`/api/v1/agent/*`. User tokens and node keys are not interchangeable.

## Endpoint overview

| Area | Endpoints | Permission |
|---|---|---|
| Auth | `POST /auth/login`, `GET /auth/sso/config`, `POST /auth/sso` (opt-in, may create a viewer; see security.md), `GET /auth/me`, `POST /auth/password` | — |
| Dashboard | `GET /dashboard?hours=` | read |
| Flows | `GET /flows` (filters: `q`, `action`, `label`, `node`, `alert_id`, `min_score`, `hours`), `GET /flows/{id}`, `POST /flows/{id}/explain` | read / advisor |
| Alerts | `GET /alerts`, `GET/PATCH /alerts/{id}`, `POST /alerts/{id}/triage`, `POST /alerts/{id}/narrate` | read / triage / advisor |
| Rules | `GET /rules`, `GET /rules/hygiene`, `GET/PATCH/DELETE /rules/{id}` | read / approve |
| Drafts | `GET /drafts`, `POST /drafts`, `POST /drafts/simulate`, `POST /drafts/{id}/approve`, `POST /drafts/{id}/reject` | read / author / approve |
| Bundles | `GET /bundles`, `POST /bundles/publish`, `POST /bundles/{v}/advance`, `POST /bundles/{v}/rollback` | read / approve |
| Fleet | `GET /nodes`, `POST /nodes/enrollment-tokens`, `POST /nodes/{id}/revoke` | read / fleet |
| Users | `GET/POST /users`, `PATCH /users/{id}`, `POST /users/{id}/reset-password` | users |
| Audit | `GET /audit`, `GET /audit/verify`, `GET /audit/export.csv` | audit |
| Exports | `GET /flows/export.csv`, `GET /alerts/export.csv` (same filters as the lists, 50,000 rows at most) | read |
| Notifications | `GET/POST /notifications/channels`, `PATCH/DELETE /notifications/channels/{id}`, `POST /notifications/channels/{id}/test`, `GET /notifications/deliveries` | integrations |
| NEXORA | `GET /nexora/status`, `POST /nexora/sync` (see [nexora.md](nexora.md)) | integrations |
| Claude usage | `GET /llm/usage` | read |
| System | `GET /system`, `GET /version`, `GET /pki/bundle-signing-key` | read / public |
| Agent | `POST /agent/enroll`, `GET /agent/bundle`, `POST /agent/flows`, `POST /agent/heartbeat` | node key |

## Sending flows from your own sensor

Enroll a node to obtain an API key, then POST up to 5,000 flow records per request:

```bash
curl -s https://nw.example.com/api/v1/agent/flows \
  -H "Authorization: Bearer $NODE_KEY" -H 'content-type: application/json' -d '{
  "flows": [{
    "src_ip": "10.0.0.5", "dst_ip": "203.0.113.9", "src_port": 51514, "dst_port": 443,
    "protocol": "tcp", "direction": "outbound", "ts_start": 1790000000.0, "ts_end": 1790000001.2,
    "bytes_out": 820, "bytes_in": 5120, "packets_out": 9, "packets_in": 10,
    "l7": {"tls": {"sni": "example.com", "ja3": "cd08e31494f9531f560d64c695473da9",
                   "claimed_client": "chrome"}}
  }]}'
```

The response lists accepted and rejected counts (with the first validation errors) and the
**enforced verdicts** for the batch. Apply them in your datapath, or ignore them in
monitor-only integrations. The full `FlowRecord` schema is in the OpenAPI document and in
`neurawall/core/models.py`.

## Errors

Errors return `{"error": "<code>", "message": "…"}` with 401 (unauthenticated), 403
(policy violation, e.g. RBAC, four-eyes, blast-radius gate), 404, 409 (integrity failure),
422 (validation, with `details`), 429 (rate limited) or 503 (dependency unavailable).
Every response carries an `X-Trace-Id` header that also appears in server logs.
