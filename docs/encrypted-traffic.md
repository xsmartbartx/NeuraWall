# What NeuraWall detects without decrypting

NeuraWall never decrypts traffic and never stores payloads ([ADR-0004](adr/ADR-0004-no-tls-interception.md)). It works from
flow metadata. What that covers depends on what the sensor can see.

| Signal (visible in encrypted traffic) | Used by | What it can find |
|---|---|---|
| Flow shape: bytes in and out, packet counts, durations, timing | Tier 1 anomaly engine (Isolation Forest, EWMA baselines) | A host that suddenly behaves differently, scans, floods |
| Inter-arrival timing of one flow | Beacon detector | Regular call-backs to a server (C2 beaconing) |
| Volume and direction | Exfiltration detector | Very large outbound transfers (20 MB and up) |
| TLS handshake: SNI, TLS version, JA3 / JA4, ALPN | TLS mismatch detector | A client claiming to be a browser with a non-browser fingerprint |
| DNS query names | DNS detector | DGA-looking names and DNS tunnelling |

| Needs the request visible (plain HTTP, or a sensor behind your TLS terminator) | Used by |
|---|---|
| HTTP path and query | Injection detector: SQL, command and template injection, path traversal, XSS |

**The honest limit.** On a public HTTPS service the injection detector sees nothing unless the sensor sits behind the TLS terminator
(or you already run sensor-side decryption). The Tier 1 and the signals in the first table work either way. Detectors are heuristics
with known gaps: see [evasion-report.md](evasion-report.md). A detector can only raise an alert; a person approves any rule that blocks.
