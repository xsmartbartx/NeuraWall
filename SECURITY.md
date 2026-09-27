# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 1.x | ✅ |

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through
[GitHub security advisories](https://github.com/MiejskiSurfer/NeuraWall/security/advisories/new)
with a description, affected version, reproduction steps and impact.

We aim to acknowledge reports within 3 business days and to ship a fix or mitigation for
confirmed high-severity issues within 30 days. We credit reporters unless they prefer otherwise.

Particularly valuable: bundle-signature or anti-replay bypasses, ways for model output (including
prompt injection through traffic metadata) to change enforcement without human approval,
authentication/RBAC bypasses, and audit-chain forgery.

See [docs/security.md](docs/security.md) for the security model.
