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
  JWKS, expiry, and `iss` when `SSO_ISSUER` is set) and its `email` claim is
  mapped to an **existing, active** NeuraWall user, who signs in with **their own
  NeuraWall role**. Roles, deactivation and the four-eyes approval rule are
  unchanged and still live in NeuraWall.
- It never creates users and never takes a role from the identity provider. An
  unknown or deactivated email is refused.
- Set `NEURAWALL_AUTH__SSO_REQUIRED_ORG_ID` to accept only members of one Clerk
  organisation. The Clerk instance must require verified email addresses.
- Every refusal returns the same generic 403 so a caller cannot tell which check
  failed; the endpoint shares the login IP rate limit; each success is audited as
  `auth.login.sso`.
- Password login is unaffected and remains available.

The console has no SSO button yet; a front end obtains a Clerk session token and
calls this endpoint.
