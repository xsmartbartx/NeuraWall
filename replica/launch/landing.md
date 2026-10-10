# Landing page copy: NeuraWall

Copy for the NeuraWall product page on onenexora.com (a different repository, **not edited here**). Voice: direct, careful, plain (`brand.md`). No testimonials, user counts or logos: there are none to show yet.
Angle used: "no black box" (`fixes.md`, hypothesis based on thin evidence).

## 1. Hero

**An AI-assisted network firewall that never blocks on its own.**
Claude proposes a rule. You see what it would have blocked in your own traffic. A person approves it. Then it rolls out in stages, and rolls back by itself if something looks wrong.

Button: **Try the demo** (read-only, synthetic traffic) · link: Read the docs
Image: a real screenshot of the Alerts to Approvals flow from the demo instance (**to take once the demo instance runs**).

## 2. The problem

- Firewalls that "use AI" often act on it, and when they are wrong you find out from the people they blocked.
- Rules pile up until nobody dares touch them, and encrypted traffic makes the old inspection tricks expensive.

(Written from the product's own promise and a small, thin set of public comments. No reviewer is quoted.)

## 3. How it works

1. **Watch.** Statistics, machine learning and traffic classifiers look at flow metadata. Nothing is decrypted; payloads are never stored.
2. **Propose.** Claude triages the alert and drafts a narrow rule that starts in alert-only mode. Without a Claude key, an offline advisor drafts it.
3. **Approve and roll out.** The draft is replayed against recent legitimate traffic first. You approve. A signed bundle goes to 5% of nodes, then 25%, then all, and rolls back if blocking jumps.

## 4. Features (fixes first, parity after)

- **Nothing blocks without a rule you approved.** Every drop maps to a rule id. Models can raise an alert, never a block.
- **See the blast radius before you ship.** Each draft shows how much legitimate traffic it would have matched.
- **Works on encrypted traffic without decrypting it.** Flow metadata, TLS fingerprints, DNS behaviour. *(Page "What we detect without decrypting": to be written, fix #2.)*
- **Tamper-evident history.** A hash-chained audit trail you can verify, and signed bundles nodes check themselves.
- **Keeps enforcing when the control plane is gone.** Nodes run their last signed bundle.
- **Alerts where your team already is.** Signed JSON webhooks (the body has a `text` field that Slack and Teams incoming webhooks accept; for PagerDuty or a SIEM, point it at their generic HTTP receiver), and CSV export.
- **Sign in with your NEXORA account**, or keep local accounts.

Not claimed: a "detection rate", a "false-positive rate", or "blocks X% of attacks". There is no independent measurement to cite yet (fix #1 is a published evasion report).

## 5. Pricing

See `pricing.md`. The page shows the five plans as they are today and links to the docs for what each includes.

## 6. FAQ

- **Does it decrypt my traffic?** No. It analyses metadata and never intercepts TLS (design decision ADR-0004).
- **Can the AI block my traffic by itself?** No. A model can only raise an alert or draft an alert-only rule. A person approves any rule that enforces.
- **What happens if Claude is unavailable, or I don't want to use it?** An offline advisor does the same jobs deterministically. Nothing leaves your host.
- **What happens if the control plane goes down?** Nodes keep enforcing their last signed bundle. The console being down does not change what nodes enforce.
- **What data does Claude see?** Flow metadata passed as delimited untrusted data, under an hourly call budget. Every drafted rule is schema-checked, forced to alert-only and simulated before a human sees it.
- **Can I import my current rules?** Not yet.
- **Is it open source?** No. The licence is proprietary (see LICENSE).

## 7. Final call to action

**Look at it before you trust it.** Try the read-only demo, or run the quickstart on your own machine in five minutes.
