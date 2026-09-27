# ADR-0004: No TLS interception

- **Status:** Accepted
- **Date:** 2026-09-27

## Decision
NeuraWall inspects metadata only: TLS SNI and JA3/JA4, DNS names, HTTP request line and
headers where visible (e.g. internal plaintext services, or sensor-side decryption the customer
already runs). It never decrypts traffic and never stores payloads.

## Consequences
- (+) No key management, no privacy exposure from payload retention, fewer legal constraints.
- (−) Injection detection on public HTTPS services depends on where the sensor sits (behind
  the TLS terminator). Tier 1 remains effective regardless of encryption.
