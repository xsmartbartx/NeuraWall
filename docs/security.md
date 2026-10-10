# Security model

NeuraWall is a security control, so its own compromise is the threat that matters most. The
design follows the blueprint's zero-trust model (§9): every input is untrusted, including model
output, internal RPC and the rule set itself.

## Trust boundaries

| Input | Treatment |
|---|---|
| Network traffic / flow records | Schema-validated with bounded sizes (strings, lists, 64 KB per line, 5,000 flows and 8 MB per request). Malformed records are counted and dropped. **Payloads are never collected or stored.** |
| Model outputs (Tier 1/2) | Range-checked; an out-of-range score is a fault, not a verdict. Models can only raise alerts; blocking requires an approved rule. |
| LLM output (Tier 3) | Structured output only, re-validated against strict schemas; drafts are forced to alert-only and simulated; they are never rules. |
| Policy bundles | Ed25519 signature verified **on the node** against a key pinned at enrollment, independent of TLS; versions must strictly increase (anti-replay). |
| Console / API requests | Authenticated, RBAC-authorised, validated (unknown fields rejected), rate-limited. |
| Configuration | Validated at startup; unknown keys rejected; production refuses to start without a secret key. |

## Prompt-injection defence (Tier 3)

Attackers control HTTP paths, DNS names and user agents, and those reach the LLM's context.
Defences, in order:

1. Flow content is serialised as JSON inside `<untrusted_flow_data>` tags. Any attempt to
   close or re-open that tag inside the data is neutralised, and the system prompt instructs
   the model to treat the content as data only.
2. Known injection phrasings are detected and passed to the model as `injection_markers`,
   i.e. reported as evidence of malice.
3. Output is constrained to a JSON schema and then re-validated. Invalid CIDRs, empty matches
   or unknown labels cause the draft to be discarded in favour of the deterministic advisor's.
4. Every draft is alert-only, simulated for blast radius, and requires human approval.
5. `llm_advisor` cannot import the policy engine or datapath (enforced by `import-linter`).

The worst outcome of a successful injection is a misleading draft that a human must still
approve after seeing its simulated impact.

## Identity and access

- Passwords: argon2id; at least 12 characters mixing three character classes. Admin-created
  and reset passwords must be changed at first sign-in.
- Sessions: HS256 JWTs (default 8 h). They are revoked on password change, reset or account
  disable. The console keeps the token in `sessionStorage`, and a strict CSP (`script-src 'self'`)
  limits XSS impact.
- Roles: viewer, analyst, operator, approver and admin. **Authoring** and **approving**
  enforcement changes are separate permissions. `policy.require_four_eyes` forbids approving
  your own change.
- Login throttling per client IP and per account; generic error messages; constant-work
  password checks for unknown users.
- Nodes authenticate with per-node API keys (only SHA-256 hashes stored). Enrollment tokens
  are single-use by default, expire, and are stored hashed.

## Secrets and data at rest

- The data directory is `0700`; the signing key and bootstrap password file are `0600`. The
  bootstrap password file is deleted after the first password change.
- Logs pass through a redaction filter at the logging primitive: credentials, tokens, API keys,
  cookies, JWTs and URL query strings are removed before any handler writes.
- Audit trail entries are redacted, then hash-chained (SHA-256, genesis-anchored).

## Transport

Run the control plane behind TLS (the Compose stack's Caddy obtains certificates
automatically). HSTS is sent when `public_url` is `https://`. Agents verify the control plane
certificate (`ca_bundle` for private CAs). Bundle integrity does not depend on TLS.

## HTTP hardening

CSP (`default-src 'self'; frame-ancestors 'none'`), `X-Frame-Options: DENY`,
`X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`,
`Cache-Control: no-store` on API responses, request size limits, per-client API rate limits.

## Supply chain

Dependencies are locked (`uv.lock`, `package-lock.json`). CI runs `pip-audit`, `npm audit` and
ruff's bandit-derived `S` rules. Release images are multi-arch, built with an SBOM and
provenance attestation, and run as a non-root user.

## Known limitations

- No TLS interception: L7 detection uses metadata only (blueprint ADR-0004).
- The control plane is a single process. Protect its host like any security-management plane.
- The bundle-signing key is file-backed. The `Signer` protocol lets an HSM/KMS signer replace
  `FileSigner`; this is not bundled in 1.0.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md).

## Optional single sign-on (Clerk)

Off by default. Setting `NEURAWALL_AUTH__SSO_JWKS_URL` enables
`POST /api/v1/auth/sso` with `{"token": "<Clerk session token>"}`.

What it does and does not do:

- Clerk only proves identity. The token is verified (RS256 signature against the
  JWKS, expiry, and `iss` when `SSO_ISSUER` is set). The user is found by the
  provider's user id (`sub`) first, then by the token's `email` among existing,
  active users. That user signs in with **their own NeuraWall role**. Roles,
  deactivation and the four-eyes approval rule are unchanged and still live in
  NeuraWall. An email match binds the provider id to the account only when the token
  says `email_verified: true`.
- By default it never creates users (see [Just-in-time users](#just-in-time-users)
  for the opt-in) and it never takes a role from the identity provider. An
  unknown or deactivated email is refused.
- Set `NEURAWALL_AUTH__SSO_REQUIRED_ORG_ID` to accept only members of one Clerk
  organisation. The Clerk instance must require verified email addresses.
- Every refusal returns the same generic 403 so a caller cannot tell which check
  failed; the endpoint shares the login IP rate limit; each success is audited as
  `auth.login.sso`.
- Password login remains available unless `NEURAWALL_AUTH__LOCAL_LOGIN=admin_only` (see below).

### "Sign in with NEXORA" on the console login page

Set `NEURAWALL_AUTH__SSO_LOGIN_URL` (in addition to `SSO_JWKS_URL`) and the login page shows a
button. The browser goes to the account app, which returns it here with a short-lived Clerk token
in the URL **fragment** (never sent to a server, `Referer` or access log). A random `state` the
console generated first must come back unchanged; a token it did not ask for is discarded without
calling the server. The fragment is removed from the address bar immediately.

Also set `NEURAWALL_AUTH__SSO_AUDIENCE` so a Clerk token minted for another service is refused. The
token comes from a dedicated short-lived Clerk JWT template that sets that audience.

### Just-in-time users

Set `NEURAWALL_AUTH__SSO_JIT=true` to let a verified member of your NEXORA organisation sign in
without an admin creating the account first. The first sign-in creates a **viewer**; an admin
promotes the user on the Users page.

- Refused at startup unless `SSO_JWKS_URL` and `SSO_REQUIRED_ORG_ID` are set: without an
  organisation any identity-provider user would get an account.
- The token must carry `email_verified: true` (add it to the Clerk JWT template). Anything else,
  including the string `"true"`, is refused. With JIT on this also applies to signing in as an
  existing user by email: an unverified token is refused rather than linked.
- A role is never read from the token. Users are matched by the provider's user id, so a changed
  email does not create a second account. An existing user with the same email is linked on their
  first SSO sign-in; if that email is already linked to a different identity, sign-in is refused.
- Provisioned users have no usable password: password sign-in and admin password resets are refused
  for them. Provisioning is audited (`auth.sso.provision`).
- SSO sessions last one hour by default when `SSO_JIT` is on (`SSO_SESSION_TTL_SECONDS` to change).
  Removing someone from the organisation stops new sign-ins at once and their session within that time.
- `NEURAWALL_AUTH__LOCAL_LOGIN=admin_only` keeps password sign-in for admins (break-glass) and refuses it
  for everyone else, with the same error as a wrong password.


## Webhooks

Webhooks (Integrations page) send alerts and pending approvals to a URL an administrator chose. Because
that makes the server issue requests on someone's say-so, every send, not only the save, enforces:

- `https` only, no credentials in the URL, a host *name* (not an IP literal).
- The name is resolved and **every** address must be a public one. Loopback, private ranges, link-local
  (including `169.254.169.254`), carrier-grade NAT, multicast, reserved and IPv4-mapped IPv6 internal
  addresses are refused. One bad answer among good ones refuses the whole name.
- The connection goes to the address that was checked, with the original host name for TLS, so DNS cannot
  answer differently a moment later. A refused address is never retried.
- No redirects, a five second timeout, a 64 KB body.

Each request carries `X-NeuraWall-Timestamp` and `X-NeuraWall-Signature: sha256=HMAC(secret, "<timestamp>.<body>")`.
The signing secret is derived from the server key and a per-channel nonce, shown once, and never stored.
Rotating a channel changes its nonce. Rotating `auth.secret_key` changes every channel's secret.
The URL itself can be a secret (Slack's are), so the API only ever returns its host.
Alert messages include the source and destination addresses: send them only to receivers you trust.

## CSV exports

Flows, alerts and the audit trail export as CSV with the same permission as the matching list. Cells that start
with `=`, `+`, `-`, `@`, a tab or a carriage return get a leading apostrophe so a spreadsheet does not run them
as formulas (hostnames and alert titles come from network traffic an attacker controls). An export stops at
50,000 rows and is itself recorded in the audit trail.

## Public demo

`NEURAWALL_AUTH__DEMO_PUBLIC_LOGIN=true` adds a "Try the demo" button that signs a visitor in as a read-only
viewer for 30 minutes (20 per hour per address). It is for a **separate demo instance** and the server refuses
to start unless `demo_mode` is on, and refuses if the instance is linked to NEXORA, has Stripe keys or a Claude
API key. If an administrator changes the demo account's role or deactivates it, the button stops working.
