# Parity: NeuraWall x NEXORA linked mode

Date 2026-10-10. In this self-audit the "original" is what NEXORA promises and what a NEXORA tenant must do; the "clone" is the repo on branch `feat/nexora-link` (uncommitted). Before the work the matrix had 15 of 32 rows at `yes`; now 21 of 34.

**Verdict: not shippable yet, and not because of NeuraWall.** Both open must-haves are `partial` because the other half lives in the NEXORA repo (N1 entitlements endpoint, N4 the `email_verified` claim), which I did not touch. On the NeuraWall side both are built and tested against fakes. No open S1 or S2 bug. Score 85.4 clears the 80 bar.

**Layout score: not measured.** There is no external original to compare against, and the only visual change is the token fix (contrast), which a colour-blind edge diff would ignore by design. Reference screenshots were taken in the browser instead (see `test-plan.md`).

## Parity: 85.4 / 100

features 85.4  (30 counted, must-haves 13 of 15 done)

Not shippable yet: 2 must-have features are not done.

## By area, weakest first
- marketing                      0.0  (1 features)
- docs                          50.0  (1 features)
- onboarding                    50.0  (1 features)
- platform                      64.3  (3 features)
- operations                    66.7  (2 features)
- identity                      75.0  (2 features)
- access                        80.0  (2 features)
- integrations                  83.3  (2 features)
- detection                    100.0  (1 features)
- enforcement                  100.0  (3 features)
- approvals                    100.0  (1 features)
- audit                        100.0  (1 features)
- fleet                        100.0  (1 features)
- billing                      100.0  (5 features)
- reporting                    100.0  (1 features)
- deployment                   100.0  (1 features)
- quality                      100.0  (1 features)
- accessibility                100.0  (1 features)

## Missing, in build order
- [must] identity: Sign in works for a NEXORA customer who has no NeuraWall user, partial  (built (auth.sso_jit, viewer only); needs email_verified in the Clerk JWT template and the flag on (N4))
- [must] platform: NeuraWall identity and entitlements come from NEXORA Core (org-scoped), partial  (plan pull and org binding built; identity stays a local role projection (deviation from T-2, see architecture D6); needs N1 on the NEXORA side)
- [should] marketing: Console screenshots and demo on the product page, no  (needs the separate demo instance running; then screenshots)
- [should] access: MFA / TOTP for console users, partial  (SSO-only mode (auth.local_login=admin_only) delegates MFA to Clerk; no TOTP for local accounts)
- [should] docs: Public docs for NeuraWall on docs.onenexora.com, partial  (docs/nexora.md written in this repo; the docs.onenexora.com entry is N5)
- [should] onboarding: Visitor self-serve trial or hosted demo, partial  ('Try the demo' guest sign-in built and guarded; the separate demo instance is not deployed)
- [should] platform: Usage events visible in NEXORA console Usage feed, partial  (sender built (outbox, retries, counts only); needs N2 on the NEXORA side)
- [could] operations: High availability control plane (more than one replica), no  (deliberate: in-memory baselines; Helm pins replicas 1)
- [could] integrations: SIEM / syslog export of alerts and audit, partial  (webhook JSON and CSV export; no syslog or CEF)

## Left out on purpose (not scored)
- Org model (one account -> many orgs -> NeuraWall tenant): decided: one installation = one organisation (D2); two orgs need two installations; multi-tenant is a separate project
- eBPF/XDP datapath backend: deliberately later (ADR-0002)
- SOC 2 / ISO 27001: process and audit rather than code

## Yours, not in the original (not scored)
- TLS interception for L7 on encrypted traffic

## Behaviour differences (promised vs built)

| flow | promised / expected | built | fix or keep |
| --- | --- | --- | --- |
| F04 sign in | a NEXORA customer clicks "Open NeuraWall" and is in | in once N4 is done and `NEURAWALL_AUTH__SSO_JIT=true`; until then still refused | keep; do N4 |
| F04 clicks | | 1 click when already signed in at NEXORA (was: refused) | win |
| F03 plan | one bill in NEXORA | plan pulled hourly; local checkout refused | keep |
| F03 outage | n/a | plan survives 4 + 3 days, enforcement never changes | keep |
| F01 Claude | Pro "billed separately", Business "budget included" | Pro: own key; Business/Enterprise: metered monthly budget | fix the pricing page wording (N6) and set real numbers |
| F07 visitor | trial or demo from the product page | guest sign-in built; no demo instance deployed | deploy a separate instance (not done) |
| alerts | "NeuraWall tells me when something happens" | signed webhooks with retries; no email | keep (D10) |

## Top five to do next

1. NEXORA side: N1 `/v1/entitlements/neurawall`, N2 `/v1/events`, N4 JWT template with `email_verified` (unblocks both must-haves).
2. Decide and set the Claude budget numbers; change the pricing page text (N6).
3. Stand up the separate demo instance and take the product-page screenshots.
4. Keyboard access to table rows, focus trapping in dialogs, axe scan (`design/components.md`).
5. Account erasure vs. the hash-chained audit log (log `user:<id>` instead of emails).
