# Pricing

Read 2026-10-10. **Prices change; recheck before quoting any of these.**

## Where NeuraWall stands today (`modules/billing/plans.py`, onenexora.com/pricing)

| plan | monthly | yearly | nodes | retention | Claude |
| --- | --- | --- | --- | --- | --- |
| Community | $0 | n/a | 1 | 7 days | offline advisor |
| Pro | $149 | $1,490 | 5 | 7 days | your own Anthropic key |
| Business | $499 | $4,990 | 25 | 30 days | monthly call budget included |
| Enterprise | $3,000 | $30,000 | 100 | 90 days | monthly call budget included |
| Enterprise Dedicated | from $5,000 | quoted | custom | custom | your own key |

Yearly is about two months free (17%).

## What others charge (public information, read today)

| product | what it is | price read | source |
| --- | --- | --- | --- |
| Sophos Firewall Home | full firewall, free, home use, 4 cores | $0, "available at no cost for home users"; commercial use not addressed | [sophos.com](https://www.sophos.com/en-us/products/free-tools/sophos-xg-firewall-home-edition) |
| Zenarmor (OPNsense plugin) | NGFW layer on an open firewall | aggregator listings say about $50 a month for Business and about $369 a year for SOHO. **Not confirmed on the vendor's own pricing page** (it returned 404 to me) | [Capterra](https://www.capterra.com/p/265166/Zenarmor/reviews/), [OPNsense shop](https://shop.opnsense.com/product/zenarmor/) |
| Palo Alto, Fortinet, Darktrace | enterprise appliances and NDR | not published; sold through partners | (no page to cite) |

## What reviewers said about price

From `feedback.md`: "too complicated or expensive to run" came up in 4 of 8 comments, one source, thin, and all four were about big appliances, not about NeuraWall. **Nothing was said about billing, cancelling or renewals**, so there is no billing complaint to design around from evidence.

## Observations (opinions, not evidence)

- Against the free and low-priced options above, $149 for five nodes is a business-grade price. That fits "teams with a security budget"; it does not fit "small teams who can't afford an appliance". The two angles in `fixes.md` pull in different directions. Decide who the first customer is before changing numbers.
- Community (free, one node, offline advisor) is the right on-ramp for the "look before you trust" angle.
- Pro "billed separately" is now true by mechanism (own key). The pricing page should say "bring your own Anthropic key" instead.
- The Business and Enterprise call budgets (3,000 and 15,000 a month in the code) are placeholders. Do not publish a number until you have seen real Claude costs per call.

## Before changing the site (NEXORA repo)

1. Pro row: "Claude AI: bring your own Anthropic key".
2. Business and Enterprise rows: replace "usage budget included" with the real number once decided.
3. Say where billing happens: in the NEXORA console, one place, cancel there.

## Stripe

Already created and live (from the deploy notes; not touched here): products and prices with lookup keys `neurawall_<plan>_<month|year>`, a webhook, and a NeuraWall-specific Customer Portal configuration. **No new Stripe object is needed.** In linked mode these must be owned by NEXORA Core (N3), which is a change to live Stripe wiring and waits for your explicit go.

## Billing behaviour already in the product

One-click cancel through the Customer Portal, 3-day grace after a failed renewal, plan downgrades never touch enforcement. Renewal emails come from Stripe (NeuraWall sends none).
