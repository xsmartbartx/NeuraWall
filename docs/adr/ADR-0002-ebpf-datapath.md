# ADR-0002: Datapath technology

- **Status:** Accepted (revised for 1.0)
- **Date:** 2026-09-27

## Context
The blueprint targets an eBPF/XDP datapath in Rust/C at 10 Gbps line rate. Release 1.0 must be
deployable on ordinary Linux hosts and gateways by small teams, and verifiable in CI.

## Decision
Ship a pluggable `EnforcementBackend` protocol with two backends:
- **nftables** (Linux): static L3/L4 rules compile into an atomic `inet neurawall` table; dynamic
  per-flow and per-host verdicts go into timed sets (`dyn_drop4/6`, `quarantine4/6`).
- **dry-run**: computes everything and touches nothing (evaluation, monitor-only deployments).

eBPF/XDP remains the roadmap backend behind the same protocol.

## Consequences
- (+) Kernel-speed enforcement for static rules; nftables is available on every modern distro.
- (+) The same bundle and verdict semantics carry over to an eBPF backend later.
- (−) Throughput is bounded by the netfilter path rather than XDP; not suitable for multi-10 Gbps
  inline deployments in 1.0.
- Rules constrained by direction are enforced dynamically, never statically, because the kernel
  ruleset does not know the site's local networks (never over-block).

## Alternatives considered
DPDK (dedicated NICs/cores; poor fit for general hosts). iptables (legacy, non-atomic updates).
