# Brand: NeuraWall

This is the user's own product, so there is no original to rebrand away from. The brand step becomes: screen the existing name honestly, keep or fix the palette, write down the voice, and sweep for incumbents' names.
Checks run 2026-10-10. They are screening checks, not legal clearance; a trademark lawyer should search before money is spent on the name.

## Name: NeuraWall (keep, with three things to fix)

| check | result |
| --- | --- |
| domain neurawall.com, .net | **whois says no match: not registered** (2026-10-10) |
| domain neurawall.io, .ai, .dev, .app | no DNS delegation found; whois returned nothing usable. **Confirm at a registrar** |
| GitHub | no `neurawall` user or organisation. Six unrelated repositories carry the name, all 0 to 3 stars: an AI-driven firewall class project, an "AI-powered HTTP security middleware", a wallet, a wallpaper tool |
| **PyPI** | **`neurawall` is taken**: another author's "AI-powered HTTP security middleware for FastAPI", version 0.3.0. This repo's package is also called `neurawall` (`pyproject.toml`) |
| npm | free (404) |
| web search for the exact name | no vendor or product found; only the generic "AI firewall" category (Akamai, Robust Intelligence, aiFWall, Radware articles) |
| US trademark (USPTO) | **to run**, classes 9 and 42 |
| EU trademark (EUIPO / TMview) | **to run** |
| Canada, WIPO | **to run** |
| App Store, Google Play | **not applicable** (no mobile app); to run if one is planned |
| X, Instagram, TikTok, LinkedIn handles | **to run** |

What to do, in order:

1. **Register neurawall.com** (and .net, plus .io or .ai if you want them). Nobody has it. I cannot buy domains for you.
2. **The PyPI name.** Nothing here publishes to PyPI (releases attach the wheel to GitHub), so nothing is broken today. But `pip install neurawall` would install someone else's software, and a customer pointing a mirror at PyPI while installing your wheel is a dependency-confusion risk. Consider distributing under a distinct name such as `nexora-neurawall` (decision for you; not changed).
3. **Category crowding.** "AI firewall" now names a class of LLM-prompt filters (Akamai, Robust Intelligence, aiFWall). NeuraWall is a network firewall. Say "AI-assisted network firewall" in copy so nobody takes it for a prompt filter. This is a clarity problem more than a legal one.
4. Run the trademark rows above (or hand them to a lawyer) before investing in the logo.

## Palette: keep, now AA-clean

Dark-first, one green accent. There is no incumbent brand colour to avoid (`brand.json` lists no colours). Roles and values are in `replica/design/tokens.json` (dark) and `tokens.light.json`; both pass WCAG AA with zero failures (checked this session). Platform consistency with NEXORA's own palette was not checked.

## Logo brief

Idea: a wall with a gate you control: filtering, and a human holding the key. Wordmark "NeuraWall" with a simple mark (a wall of bricks with one opening, or a shield with a notch). Must read at 16 px (favicon) and at 1024 px (app icon, no transparency). Deliverables: SVG, favicon set, 1200x630 social image. It must not use a padlock-on-brain or a circuit-board cliché (every AI-security vendor does). The current `console/public/favicon.svg` is a working placeholder.

## Voice

Three words, each with what it does not mean:

- **Direct, not blunt.** Say what happened and what to do; do not blame the user.
- **Careful, not timid.** A firewall console should sound sure about what it will and will not do (the model proposes, a human approves) and plain about what it does not know.
- **Plain, not casual.** No jokes in error states and no jargon where a word everyone knows exists.

| do | don't |
| --- | --- |
| "The Claude advisor is off on this plan. The offline advisor still drafts rules." | "Oops! AI features are unavailable." |
| "Enforcement is not affected." (in every plan or sync warning) | "Something went wrong." |
| "Copy this signing secret now. It is shown only once." | "Please make sure to save this somewhere safe!!" |
| "This installation belongs to a NEXORA organisation, so the plan is managed there." | "Billing is handled elsewhere." |
| "Webhooks must use https and a public address." | "Invalid URL." |

The strings written in this build (Billing, Integrations, Settings, login) were written to this guide. I did not rewrite older screens.

## Sweep

`sweep.py` for the incumbents (Palo Alto, Fortinet, FortiGate, Darktrace, Vectra, CrowdStrike, Sophos, Check Point) and their domains: **clean**, nothing found in the repository.
