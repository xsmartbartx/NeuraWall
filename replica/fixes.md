# Fixes and angle

## Read this first: the evidence is thin

Sample: **8 reviews from 1 source (Hacker News comments, read through its official Algolia API)**, about firewalls and AI security tools in general. NeuraWall itself has no public reviews yet (beta). I could not reach more: G2 returned 403 (I did not work around it), the Trustpilot page for Darktrace holds recruitment complaints and spam reports, not product reviews, and Reddit needs an authorised API client. No star ratings exist in the sample. Every theme below is **thin** (fewer than 3 reviews or one source). This supports a hypothesis to test with real users, not a ranking to build a roadmap on. The sheet is `reviews.csv`; the ranking is `feedback.md`.

"Original" here is the category incumbents (Palo Alto, Fortinet, Darktrace, Cisco), because the product being audited is NeuraWall's own.

## 1. What they hate (thin)

| problem | reviews | sources | quote |
| --- | --- | --- | --- |
| Too complicated or expensive to run | 4 | 1 | "Way too expensive and complicated for most if not all home users." ([HN](https://news.ycombinator.com/item?id=47504380)) |
| Encrypted traffic is hard to inspect | 3 | 1 | "TLS 1.3 with cert pinning and end-to-end encryption is making life hell for corporate compliance." ([HN](https://news.ycombinator.com/item?id=39640334)) |
| Rules grow and drift | 3 | 1 | "I found that over time ufw becomes unwieldy and it's hard to make sure you keep the rules consistent" ([HN](https://news.ycombinator.com/item?id=42755626)) |
| Doubt that "AI" security holds up | 2 | 1 | "12 bypassed with 100% confidence." ([HN](https://news.ycombinator.com/item?id=47325268)), about a prompt-injection filter, a different product class, so treat as a tone signal only |
| Inspection costs throughput | 1 | 1 | "Don't expect analysis features to run at line speed" ([HN](https://news.ycombinator.com/item?id=48589393)) |

## 2. What is missing (thin)

One person asked for an open-source router firmware to grow "next gen firewall" features with threat feeds ([HN](https://news.ycombinator.com/item?id=42256727)). That is the only request, and it is about a different product. Nothing else matched.

## 3. What is unsolved (thin)

Small teams and sites without a TLS-decrypting appliance: the comments call such appliances "way too expensive and complicated" and "a bear to configure". NeuraWall's design already answers this by analysing flow metadata and never decrypting (ADR-0004) and by running free on one node (Community).

## Where NeuraWall already lines up (from the repo, not from the reviews)

| complaint | what NeuraWall does today |
| --- | --- |
| Encrypted traffic | metadata-only, no TLS interception, works on encrypted flows |
| Rules drift | hygiene analysis (shadowed, redundant, overly broad) and blast-radius simulation before any rule applies |
| Distrust of AI | the model can only propose; a policy engine decides; a human approves; drafts are alert-only; an offline advisor works without Claude |
| Cost and complexity | free Community plan, one-command compose quickstart |

## Fix plan (small, and flagged as hypotheses)

| # | what | size | skill | evidence |
| --- | --- | --- | --- | --- |
| 1 | Publish a **detector evasion report**: run known bypass techniques (homoglyphs, base64, fragmentation analogues for the L7 classes) against Tier 2 and publish what is caught and what is not | M | replica-test | AI-trust theme, 2 reviews, thin |
| 2 | A **"what we see without decrypting"** page in the docs and on the product page | S | replica-launch | TLS theme, 3 reviews, thin |
| 3 | **One-click cleanup draft** from a rule hygiene finding (propose the removal or tightening, simulate, approve) | M | replica-build | rules theme, 3 reviews, thin; the Cisco AI-for-rules quote is sceptical in tone |
| 4 | Show the **blast radius and last-match count on the Rules page** so drift is visible without opening each rule | S | replica-build | rules theme, thin |

Added to `features.csv` with `original = no`. Pricing and billing complaints: none appeared, so nothing goes to `/replica-launch` from this.

## The angle (hypothesis)

1. **No black box.** For small security teams who don't trust an AI to block traffic on its own, NeuraWall lets Claude propose and a human approve, with the blast radius shown first. *Evidence: thin (2 reviews, 1 source) plus the product's own design rule.*
2. **No decryption.** For teams who can't afford or run a TLS-decrypting appliance, NeuraWall finds threats in encrypted traffic from metadata, on one host. *Evidence: thin (3 reviews, 1 source) plus ADR-0004.*
3. **No rule graveyard.** For teams whose firewall rules grow until nobody dares touch them, NeuraWall replays every change against real traffic and flags the dead and overlapping ones. *Evidence: thin (3 reviews, 1 source).*

**Recommendation: lead with 1 ("no black box").** It is the one every NeuraWall control already serves, it is the product's stated promise ("never silently drops your traffic"), and it is the least tied to a competitor's weakness. Test 2 and 3 as supporting lines. Do not name an incumbent in the product name, ads or listing.

## What would make this real

Ten conversations with people who run a small firewall or an NDR tool, or 30+ reviews from at least three sources. Until then, treat this as a positioning bet.
