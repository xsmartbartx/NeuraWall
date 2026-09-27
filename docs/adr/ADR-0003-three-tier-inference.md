# ADR-0003: Three-tier inference stack

- **Status:** Accepted
- **Date:** 2026-09-27

## Decision
- **Tier 1** (statistical, unsupervised) scores every flow: Isolation Forest over flow features,
  EWMA volume baselines per (source, service, hour-of-week), DNS label entropy, and flood/scan
  detection relative to the **population** connection rate.
- **Tier 2** (L7 metadata detectors with calibrated confidences and attributions) runs on
  escalated flows (score ≥ 0.6) and flows with L7/beacon/volume signals, rate-limited per
  second. It emits `novel` when Tier 1 is confident but no detector explains the flow.
- **Tier 3** (Claude) triages high-severity and ambiguous (0.4–0.7) alerts, budgeted per hour.

Authority: models can raise alerts; only approved rules block.

## Consequences
- (+) Works on encrypted traffic (Tier 1); explainable detections (attributions everywhere).
- (−) Tier 2 detectors are engineered heuristics in 1.0; supervised models trained on
  customer-labelled data are a roadmap item.
- Lesson recorded: a per-host rate baseline produced ~12% false "novel" labels on new hosts;
  flood detection now compares against the population rate with an absolute floor.
