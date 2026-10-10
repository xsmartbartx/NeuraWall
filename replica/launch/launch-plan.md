# Launch plan

Nothing here has been done. Order matters: the first three steps are blockers.

1. **Unblock linked mode on the NEXORA side** (N1, N2, N4 in `architecture.md`). Without them the "Open NeuraWall" button still refuses NEXORA customers.
2. **Stand up the separate demo instance** (`NEURAWALL_AUTH__DEMO_PUBLIC_LOGIN=true`, own database, no Claude key, no Stripe, not linked; the server refuses to start otherwise). Take the product-page screenshots from it.
3. **Fix the copy**: pricing rows (see `pricing.md`), the "AI-assisted network firewall" wording (not "AI firewall"), and the stale "not yet integrated" line only after step 1 is live.
4. **Register neurawall.com** and decide the PyPI name question (`brand.md`).
5. **Waitlist/beta**: the existing "Talk to us" contact on onenexora.com is the only intake today. Add a one-field beta signup there. Count only real signups.
6. **Analytics and errors**: NEXORA already runs Sentry and Prometheus. The console has no product analytics; with the privacy stance of this product, prefer server-side counts (the usage events) over a browser tracker. Decide before adding any.
7. **Where to post**: Hacker News (Show HN) with the "never blocks on its own" fix as the lead and the demo link. Communities of people who run small firewalls or Suricata/Zeek: I did not find specific threads (Reddit needs an authorised client; G2 refused). Build the list by hand from the sites where you already read.
8. **First 10 users**: people you know who run a firewall or an IDS for a small team. Ask them to run the quickstart and watch the first approval. Offer Pro free for a quarter in exchange for permission to quote them. Quotes only with consent.
9. **Evidence to publish with the launch** (fix #1 and #2): the detector evasion report and the "what we detect without decrypting" page. They answer the two doubts the research found.

## Not applicable

- App Store and Google Play listing: there is no mobile app, so `listing.py` was not run and `listing.json` was not written.
- Product Hunt: low fit for this audience; Hacker News first.
- Testimonials, user counts, ratings, "trusted by": none exist and none were invented.

## Legal and trust items still open

Terms and Privacy on onenexora.com are marked draft with no reviewed entity. A launch that asks for money should not go out on drafts.
