"""Generate the NeuraWall product site (neurawall/services/control_plane/site/*.html).

The site is plain HTML and CSS: no framework, no inline scripts (the control plane's CSP
forbids them). Pages share a header and footer, so they are generated from one place.

    uv run python scripts/build_site.py

Plan names and prices mirror neurawall/modules/billing/plans.py; keep them in step.
"""

from __future__ import annotations

import html
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "neurawall/services/control_plane/site"
DOCS = "https://docs.onenexora.com"
NEXORA = "https://onenexora.com"
VIGILO = "https://vigilo.onenexora.com"

LOGO = (
    '<svg viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="7" fill="var(--card)" '
    'stroke="var(--line)"/><path d="M6 9h20M6 16h20M6 23h20" stroke="var(--line)" stroke-width="2"/>'
    '<path d="M11 9v7M21 16v7M16 23v-7" stroke="var(--accent)" stroke-width="2.4" stroke-linecap="round"/>'
    '<circle cx="16" cy="16" r="2.6" fill="var(--accent)"/></svg>'
)

ICONS = {
    "shield": '<path d="M12 3l8 3v6c0 5-3.4 8.4-8 9-4.6-.6-8-4-8-9V6l8-3z"/><path d="M9 12l2 2 4-4"/>',
    "eye": '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
    "lock": '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/>',
    "chain": '<path d="M10 14a4 4 0 005.7 0l3-3a4 4 0 00-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 00-5.7 0l-3 3A4 4 0 0011 18.7l1-1"/>',
    "bell": '<path d="M6 16V11a6 6 0 0112 0v5l2 2H4l2-2z"/><path d="M10 21h4"/>',
    "wifi": '<path d="M3 9a14 14 0 0118 0"/><path d="M6 12.5a9 9 0 0112 0"/><path d="M9 16a4.5 4.5 0 016 0"/><circle cx="12" cy="19" r="1"/>',
    "user": '<circle cx="12" cy="8" r="4"/><path d="M4 21c1-4 4-6 8-6s7 2 8 6"/>',
    "layers": '<path d="M12 3l9 5-9 5-9-5 9-5z"/><path d="M3 13l9 5 9-5"/>',
    "refresh": '<path d="M20 11a8 8 0 00-14-4L4 9"/><path d="M4 4v5h5"/><path d="M4 13a8 8 0 0014 4l2-2"/><path d="M20 20v-5h-5"/>',
}


# ---------------------------------------------------------------- markdown (just what our docs use)
_BOLD = re.compile(r"\*\*(.+?)\*\*")
_ITALIC = re.compile(r"(?<![\w*])\*([^*\s][^*]*?)\*(?![\w*])")
_LINK = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)")


def _inline(text: str) -> str:
    """Code spans, bold and links; everything else is escaped."""
    out: list[str] = []
    pos = 0
    for m in re.finditer(r"(`+)(.+?)\1", text):
        out.append(_inline_plain(text[pos : m.start()]))
        out.append(f"<code>{html.escape(m.group(2).strip())}</code>")
        pos = m.end()
    out.append(_inline_plain(text[pos:]))
    return "".join(out)


def _inline_plain(text: str) -> str:
    text = html.escape(text, quote=False)
    text = _BOLD.sub(r"<strong>\1</strong>", text)
    text = _ITALIC.sub(r"<em>\1</em>", text)
    return _LINK.sub(r'<a href="\2">\1</a>', text)


def _cell(text: str) -> str:
    text = text.strip().replace("\\|", "|")
    if len(text) > 2 and text.startswith("`") and text.endswith("`"):
        return f"<code>{html.escape(text[1:-1])}</code>"  # a whole-cell payload may hold backticks
    return _inline(text)


def _split_row(line: str) -> list[str]:
    cells = re.split(r"(?<!\\)\|", line.strip())
    return cells[1:-1]


def markdown_body(source: str) -> tuple[str, str]:
    """(title, html) for a small markdown subset: #/## headings, paragraphs, bullets, tables."""
    title, out = "", []
    lines = source.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
        elif line.startswith("# "):
            title = line[2:].strip()
            i += 1
        elif line.startswith("## "):
            out.append(f"<h2>{_inline(line[3:].strip())}</h2>")
            i += 1
        elif line.startswith("|"):
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                rows.append(lines[i])
                i += 1
            head, body = _split_row(rows[0]), [_split_row(r) for r in rows[2:]]
            th = "".join(f"<th>{_inline(c.strip())}</th>" for c in head)
            tr = "".join(
                "<tr>" + "".join(f"<td>{_cell(c)}</td>" for c in r) + "</tr>" for r in body
            )
            out.append(
                f'<div class="scroll"><table class="compare"><thead><tr>{th}</tr></thead><tbody>{tr}</tbody></table></div>'
            )
        elif line.startswith("- "):
            items = []
            while (
                i < len(lines)
                and (lines[i].startswith("- ") or lines[i].startswith("  "))
                and lines[i].strip()
            ):
                if lines[i].startswith("- "):
                    items.append(lines[i][2:].strip())
                else:
                    items[-1] += " " + lines[i].strip()
                i += 1
            out.append("<ul>" + "".join(f"<li>{_inline(t)}</li>" for t in items) + "</ul>")
        else:
            para = []
            while i < len(lines) and lines[i].strip() and not lines[i].startswith(("#", "|", "- ")):
                para.append(lines[i].strip())
                i += 1
            out.append(f"<p>{_inline(' '.join(para))}</p>")
    return title, "\n".join(out)


def icon(name: str) -> str:
    return (
        '<span class="ico"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" '
        f'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{ICONS[name]}</svg></span>'
    )


def tile(ico: str, title: str, body: str) -> str:
    return f'<div class="tile">{icon(ico)}<h3>{title}</h3><p>{body}</p></div>'


def page(*, title: str, description: str, path: str, current: str, body: str) -> str:
    def cur(name: str) -> str:
        return ' aria-current="page"' if name == current else ""

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<meta name="description" content="{description}">
<meta name="color-scheme" content="light dark">
<link rel="canonical" href="https://neurawall.onenexora.com{path}">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<meta property="og:title" content="{title}">
<meta property="og:description" content="{description}">
<meta property="og:type" content="website">
<link rel="stylesheet" href="/site.css">
<script src="/site.js" defer></script>
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<div class="parent"><div class="wrap">
  <a class="brand" href="{NEXORA}">NEXORA</a><span class="sep">/</span>
  <a href="{NEXORA}/products">Products</a><span class="sep">/</span><span>NeuraWall</span>
  <div class="right"><a href="{VIGILO}">Vigilo</a><a href="{DOCS}">Docs</a><a href="https://status.onenexora.com">Status</a></div>
</div></div>
<nav class="main" aria-label="NeuraWall"><div class="wrap">
  <a class="logo" href="/">{LOGO}NeuraWall</a>
  <ul>
    <li><a href="/#how"{cur("how")}>How it works</a></li>
    <li><a href="/#features">Features</a></li>
    <li><a href="/security/"{cur("security")}>Security</a></li>
    <li><a href="/pricing/"{cur("pricing")}>Pricing</a></li>
    <li><a href="/docs/"{cur("docs")}>Docs</a></li>
  </ul>
  <div class="cta"><a class="btn ghost small" href="/app/">Sign in</a><a class="btn primary small" href="/pricing/">Get started</a></div>
</div></nav>
<main id="main">
{body}
</main>
<footer><div class="wrap">
  <div class="cols">
    <div><a class="logo" href="/">{LOGO}NeuraWall</a><p>The AI-assisted firewall that never blocks on its own.<br>A <a href="{NEXORA}">NEXORA</a> product.</p></div>
    <div><h4>Product</h4><ul><li><a href="/#how">How it works</a></li><li><a href="/#features">Features</a></li><li><a href="/pricing/">Pricing</a></li><li><a href="/security/">Security</a></li></ul></div>
    <div><h4>Resources</h4><ul><li><a href="/docs/">Documentation</a></li><li><a href="/api/docs">API reference</a></li><li><a href="https://status.onenexora.com">Status</a></li><li><a href="{NEXORA}/changelog">Changelog</a></li><li><a href="/app/">Open the console</a></li></ul></div>
    <div><h4>NEXORA</h4><ul><li><a href="{NEXORA}">Platform</a></li><li><a href="{VIGILO}">Vigilo</a></li><li><a href="{NEXORA}/legal/privacy">Privacy</a></li><li><a href="{NEXORA}/legal/terms">Terms</a></li><li><a href="mailto:hello@onenexora.com">Contact</a></li></ul></div>
  </div>
  <div class="base"><span>© 2026 NEXORA. NeuraWall is proprietary software.</span><span>Prices in USD, billed in the NEXORA console.</span></div>
</div></footer>
</body>
</html>
"""


PIPELINE = """
<div class="pipeline">
<svg viewBox="0 0 960 220" role="img" aria-label="Flow metadata is scored, Claude proposes an alert-only rule, a person approves it after a replay, then it rolls out to 5 percent, 25 percent, then all nodes">
  <defs><linearGradient id="g" x1="0" x2="1"><stop offset="0" stop-color="var(--accent)" stop-opacity=".0"/><stop offset="1" stop-color="var(--accent)"/></linearGradient></defs>
  <g font-family="-apple-system, Segoe UI, sans-serif" text-anchor="middle">
    <g><rect x="8" y="50" width="200" height="120" rx="18" fill="var(--card)" stroke="var(--line)"/>
      <text x="108" y="92" font-size="13" fill="var(--muted)">1 · WATCH</text><text x="108" y="124" font-size="20" font-weight="650" fill="var(--ink)">Flow metadata</text><text x="108" y="148" font-size="13" fill="var(--muted)">never decrypted</text></g>
    <g><rect x="256" y="50" width="200" height="120" rx="18" fill="var(--card)" stroke="var(--line)"/>
      <text x="356" y="92" font-size="13" fill="var(--muted)">2 · PROPOSE</text><text x="356" y="124" font-size="20" font-weight="650" fill="var(--ink)">Claude drafts</text><text x="356" y="148" font-size="13" fill="var(--muted)">alert-only rule</text></g>
    <g><rect x="504" y="50" width="200" height="120" rx="18" fill="var(--card)" stroke="var(--accent)" stroke-width="2"/>
      <text x="604" y="92" font-size="13" fill="var(--accent)">3 · APPROVE</text><text x="604" y="124" font-size="20" font-weight="650" fill="var(--ink)">You decide</text><text x="604" y="148" font-size="13" fill="var(--muted)">after a replay</text></g>
    <g><rect x="752" y="50" width="200" height="120" rx="18" fill="var(--card)" stroke="var(--line)"/>
      <text x="852" y="92" font-size="13" fill="var(--muted)">4 · ROLL OUT</text><text x="852" y="124" font-size="20" font-weight="650" fill="var(--ink)">5% → 25% → all</text><text x="852" y="148" font-size="13" fill="var(--muted)">auto-rollback</text></g>
  </g>
  <g stroke="var(--accent)" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round">
    <path d="M214 110h30m-7 -6l7 6-7 6"/><path d="M462 110h30m-7 -6l7 6-7 6"/><path d="M710 110h30m-7 -6l7 6-7 6"/></g>
</svg>
</div>
"""


def home() -> str:
    body = f"""
<section class="hero"><div class="wrap">
  <p class="eyebrow">NeuraWall · AI-assisted network security</p>
  <h1>A firewall that never blocks on its own.</h1>
  <p class="lede">Claude proposes the rule. You see what it would have blocked in your own traffic. A person approves it, and it rolls out in stages.</p>
  <div class="actions"><a class="btn primary" href="/pricing/">Start free</a><a class="btn line" href="{DOCS}">Read the docs</a></div>
  <p class="fine">Free for one node. Sign in with your NEXORA account.</p>
  {PIPELINE}
</div></section>

<section id="how"><div class="wrap">
  <div class="center"><h2>Watch. Propose. Approve.</h2>
  <p class="sub">Three tiers of inference raise the alert. Only a rule a person approved can ever block.</p></div>
  <div class="steps">
    <div class="step"><h3>Watch</h3><p>Statistics, machine learning and traffic classifiers read flow metadata. Nothing is decrypted, and payloads are never stored.</p></div>
    <div class="step"><h3>Propose</h3><p>Claude triages the alert and drafts a narrow rule that starts alert-only. Without a Claude key, an offline advisor drafts it on your own host.</p></div>
    <div class="step"><h3>Approve and roll out</h3><p>The draft is replayed against recent legitimate traffic first. A signed bundle goes to 5% of nodes, then 25%, then all, and rolls back if blocking jumps.</p></div>
  </div>
</div></section>

<section class="dark" id="trust"><div class="wrap split">
  <div>
    <p class="eyebrow" style="color:var(--glow)">No black box</p>
    <h2>See the blast radius before you ship.</h2>
    <p class="sub" style="margin-bottom:0">Every draft shows how much of your legitimate traffic it would have matched. Every drop maps to a rule id you approved. Models can raise an alert, never a block.</p>
    <ul class="checks">
      <li>Replay against recent traffic before approval</li>
      <li>Optional four-eyes: the author cannot approve their own rule</li>
      <li>Downgrading a plan never changes what your nodes enforce</li>
    </ul>
  </div>
  <div class="panel" role="img" aria-label="Illustration: a drafted rule with a replay result (sample values)">
    <div class="head">Example draft · Quarantine host</div>
    <div class="row"><span class="k">Proposed by</span><span>Tier 3 advisor</span></div>
    <div class="row"><span class="k">Mode</span><span class="warn">alert-only</span></div>
    <div class="row"><span class="k">Matched, last 24 h</span><span>312 flows</span></div>
    <div class="row"><span class="k">Legitimate flows hit</span><span class="ok">0</span></div>
    <div class="row"><span class="k">Rollout</span><span>5% → 25% → 100%</span></div>
    <div class="row"><span class="k">Awaiting</span><span class="ok">approval</span></div>
  </div>
</div></section>

<section id="features"><div class="wrap">
  <div class="center"><h2>Built to be trusted.</h2>
  <p class="sub">The parts a security team asks about first.</p></div>
  <div class="grid">
    {tile("eye", "Works on encrypted traffic", "Flow metadata, TLS fingerprints and DNS behaviour. NeuraWall never intercepts TLS.")}
    {tile("chain", "Tamper-evident history", "A hash-chained audit trail you can verify, and signed bundles that nodes check for themselves.")}
    {tile("wifi", "Keeps enforcing offline", "If the control plane goes away, nodes keep running their last signed bundle.")}
    {tile("refresh", "Staged rollout", "5%, 25%, then everything, with automatic rollback if blocking jumps.")}
    {tile("bell", "Alerts where your team is", "Signed JSON webhooks for Slack, Teams or any receiver, plus CSV export.")}
    {tile("user", "Roles and sign-in", "Viewer to admin roles, optional four-eyes, and Sign in with your NEXORA account.")}
  </div>
</div></section>

<section class="alt"><div class="wrap">
  <div class="center"><h2>Choose how you start.</h2>
  <p class="sub">Free for one node. Add nodes and history as you grow.</p></div>
  <div class="plans">
    <div class="plan"><h3>Community</h3><div class="price">$0</div><div class="yearly">Free forever</div><ul><li>1 enforcement node</li><li>7-day retention</li><li>Offline advisor</li></ul><a class="btn line" href="/pricing/">See details</a></div>
    <div class="plan feature"><h3>Pro <span class="tag">Popular</span></h3><div class="price">$149<small> / month</small></div><div class="yearly">$1,490 billed yearly</div><ul><li>5 enforcement nodes</li><li>7-day retention</li><li>Claude with your own key</li></ul><a class="btn primary" href="/pricing/">See details</a></div>
    <div class="plan"><h3>Business</h3><div class="price">$499<small> / month</small></div><div class="yearly">$4,990 billed yearly</div><ul><li>25 enforcement nodes</li><li>30-day retention</li><li>Monthly Claude budget included</li></ul><a class="btn line" href="/pricing/">See details</a></div>
    <div class="plan"><h3>Enterprise</h3><div class="price">$3,000<small> / month</small></div><div class="yearly">$30,000 billed yearly</div><ul><li>100 enforcement nodes</li><li>90-day retention</li><li>Monthly Claude budget included</li></ul><a class="btn line" href="/pricing/">See details</a></div>
  </div>
</div></section>

<section><div class="wrap">
  <div class="center"><h2>Questions, answered.</h2></div>
  <div class="faq" style="margin-top:40px">
    <details><summary>Does it decrypt my traffic?</summary><p>No. It analyses metadata and never intercepts TLS. That is a design decision, not a missing feature.</p></details>
    <details><summary>Can the AI block my traffic by itself?</summary><p>No. A model can only raise an alert or draft an alert-only rule. A person approves any rule that enforces.</p></details>
    <details><summary>What if Claude is unavailable, or I don't want to use it?</summary><p>An offline advisor does the same jobs deterministically, and nothing leaves your host.</p></details>
    <details><summary>What happens if the control plane goes down?</summary><p>Nodes keep enforcing their last signed bundle. The console being down does not change what nodes enforce.</p></details>
    <details><summary>What data does Claude see?</summary><p>Flow metadata, passed as delimited untrusted data under a call budget. Every drafted rule is schema-checked, forced to alert-only and simulated before a person sees it.</p></details>
    <details><summary>Can I import my current rules?</summary><p>Not yet.</p></details>
    <details><summary>Is it open source?</summary><p>No. NeuraWall is proprietary software.</p></details>
  </div>
</div></section>

<section class="dark final"><div class="wrap">
  <h2>Look at it before you trust it.</h2>
  <p class="sub">Start on the free plan and run the quickstart on your own machine.</p>
  <div class="actions"><a class="btn primary" href="/pricing/">Start free</a><a class="btn line on-dark" href="{DOCS}">Read the docs</a></div>
</div></section>
"""
    return page(
        title="NeuraWall · The AI-assisted firewall that never blocks on its own",
        description="NeuraWall detects threats with three tiers of inference, drafts narrow rules with Claude, and enforces only what a person approved.",
        path="/",
        current="",
        body=body,
    )


def pricing() -> str:
    body = f"""
<section class="hero" style="padding-bottom:48px"><div class="wrap">
  <p class="eyebrow">Pricing</p>
  <h1>Start free. Grow when you need to.</h1>
  <p class="lede">One price per plan, billed in the NEXORA console. Cancel there, in one place.</p>
</div></section>
<section style="padding-top:24px"><div class="wrap">
  <div class="plans">
    <div class="plan"><h3>Community</h3><div class="price">$0</div><div class="yearly">Free forever</div><ul><li>1 enforcement node</li><li>7-day retention</li><li>Offline advisor</li><li>Signed rule bundles, audit trail</li></ul><a class="btn line" href="/app/">Sign in to start</a></div>
    <div class="plan feature"><h3>Pro <span class="tag">Popular</span></h3><div class="price">$149<small> / month</small></div><div class="yearly">$1,490 billed yearly</div><ul><li>5 enforcement nodes</li><li>7-day retention</li><li>Claude with your own Anthropic key</li></ul><a class="btn primary" href="/app/billing">Choose Pro</a></div>
    <div class="plan"><h3>Business</h3><div class="price">$499<small> / month</small></div><div class="yearly">$4,990 billed yearly</div><ul><li>25 enforcement nodes</li><li>30-day retention</li><li>Monthly Claude call budget included</li></ul><a class="btn line" href="/app/billing">Choose Business</a></div>
    <div class="plan"><h3>Enterprise</h3><div class="price">$3,000<small> / month</small></div><div class="yearly">$30,000 billed yearly</div><ul><li>100 enforcement nodes</li><li>90-day retention</li><li>Monthly Claude call budget included</li></ul><a class="btn line" href="/app/billing">Choose Enterprise</a></div>
  </div>
  <p class="note">Yearly billing is about two months free. Need more nodes, dedicated hosting or your own key at scale? <strong>Enterprise Dedicated</strong> starts at $5,000 a month. <a href="mailto:hello@onenexora.com?subject=NeuraWall%20Enterprise%20Dedicated">Talk to us</a>.</p>
</div></section>

<section class="alt"><div class="wrap">
  <h2>Compare plans</h2>
  <div class="scroll"><table class="compare">
    <thead><tr><th></th><th>Community</th><th>Pro</th><th>Business</th><th>Enterprise</th></tr></thead>
    <tbody>
      <tr><th scope="row">Enforcement nodes</th><td>1</td><td>5</td><td>25</td><td>100</td></tr>
      <tr><th scope="row">Flow and alert retention</th><td>7 days</td><td>7 days</td><td>30 days</td><td>90 days</td></tr>
      <tr><th scope="row">Claude advisor</th><td>Offline advisor</td><td>Your own Anthropic key</td><td>Monthly budget included</td><td>Monthly budget included</td></tr>
      <tr><th scope="row">Human-approved rules and replay</th><td>✓</td><td>✓</td><td>✓</td><td>✓</td></tr>
      <tr><th scope="row">Signed bundles, staged rollout</th><td>✓</td><td>✓</td><td>✓</td><td>✓</td></tr>
      <tr><th scope="row">Hash-chained audit trail</th><td>✓</td><td>✓</td><td>✓</td><td>✓</td></tr>
      <tr><th scope="row">Webhooks and CSV export</th><td>✓</td><td>✓</td><td>✓</td><td>✓</td></tr>
      <tr><th scope="row">Sign in with NEXORA</th><td>✓</td><td>✓</td><td>✓</td><td>✓</td></tr>
    </tbody>
  </table></div>
  <p class="note">Downgrading never changes what your nodes enforce. After a failed renewal there is a 3-day grace period. Renewal emails come from Stripe.</p>
</div></section>

<section><div class="wrap">
  <div class="center"><h2>Pricing questions.</h2></div>
  <div class="faq" style="margin-top:40px">
    <details><summary>Where do I pay and cancel?</summary><p>In the NEXORA console, in one place. Cancel there at any time.</p></details>
    <details><summary>What does "your own Anthropic key" mean?</summary><p>On Pro, Claude calls use your own Anthropic account, so Anthropic bills you for them directly. NeuraWall meters the calls but does not cap them.</p></details>
    <details><summary>What happens if I run out of Claude budget on Business?</summary><p>The offline advisor takes over until the period resets. Detection and enforcement are not affected.</p></details>
  </div>
</div></section>
"""
    return page(
        title="NeuraWall pricing · Start free",
        description="NeuraWall plans: Community (free), Pro, Business and Enterprise. Billed in the NEXORA console.",
        path="/pricing/",
        current="pricing",
        body=body,
    )


def security() -> str:
    body = f"""
<section class="doc"><div class="wrap">
  <p class="eyebrow">Security</p>
  <h1>Designed so the AI cannot hurt you.</h1>
  <p class="lede" style="margin-left:0">The rules that decide what is blocked are deterministic and human-approved. The models only help you find and write them.</p>

  <h2>Only approved rules can block</h2>
  <ul>
    <li>Three tiers raise alerts: statistical anomaly detection, a layer-7 classifier, and the Claude advisor. None of them can enforce.</li>
    <li>Only the policy engine blocks, and only through a rule a person approved. This boundary is enforced in the code base by an import contract, not by convention.</li>
    <li>An AI-drafted rule is schema-checked, forced to start alert-only, and replayed against recent traffic before a person ever sees it.</li>
  </ul>

  <h2>Signed and verifiable</h2>
  <ul>
    <li>Rule bundles are signed with Ed25519. Nodes verify every bundle, refuse replays, and keep the last known good one.</li>
    <li>Every change, approval and sign-in goes into a hash-chained audit trail that you can verify from the console.</li>
    <li>The audit trail records opaque user ids, not email addresses, so a person can be erased without breaking the chain.</li>
  </ul>

  <h2>What it sees</h2>
  <ul>
    <li>NeuraWall analyses flow metadata, TLS fingerprints and DNS behaviour. It does not intercept or decrypt TLS, and payloads are not stored.</li>
    <li>Claude receives flow metadata as delimited, untrusted data under a call budget. Text inside it is never treated as instructions.</li>
    <li>Without a Claude key, an offline advisor runs on your own host and nothing leaves it.</li>
  </ul>

  <h2>Access and operations</h2>
  <ul>
    <li>Roles from viewer to admin, with optional four-eyes approval. Sign-in through NEXORA creates viewers only; roles are never taken from the identity provider.</li>
    <li>Outbound webhooks are signed and SSRF-guarded: every address is checked, the connection is pinned and redirects are not followed.</li>
    <li>Plan changes never change what nodes enforce, and nodes keep enforcing when the control plane is unreachable.</li>
  </ul>

  <h2>Report a vulnerability</h2>
  <p>Follow the disclosure process in NEXORA's <a href="{NEXORA}/.well-known/security.txt">security.txt</a>. See also the <a href="{NEXORA}/security/architecture">NEXORA security architecture</a>.</p>
</div></section>
"""
    return page(
        title="NeuraWall security · Only approved rules can block",
        description="How NeuraWall keeps AI out of the enforcement path: human-approved rules, signed bundles and a tamper-evident audit trail.",
        path="/security/",
        current="security",
        body=body,
    )


def card(title: str, body: str, href: str | None = None) -> str:
    head = f'<a href="{href}">{title}</a>' if href else title
    return f'<div class="tile"><h3>{head}</h3><p>{body}</p></div>'


def docs() -> str:
    body = f"""
<section class="hero" style="padding-bottom:40px"><div class="wrap">
  <p class="eyebrow">Documentation</p>
  <h1>Learn NeuraWall.</h1>
  <p class="lede">Run it in five minutes, understand how it decides, and look up the details.</p>
  <div class="actions"><a class="btn primary" href="#quickstart">Quickstart</a><a class="btn line" href="/api/docs">API reference</a></div>
</div></section>

<section id="quickstart" style="padding-top:32px"><div class="wrap split">
  <div>
    <h2>Quickstart</h2>
    <p class="sub" style="margin-bottom:0">Five minutes, on your own machine. Demo mode streams synthetic traffic with occasional attacks, so the dashboards, alerts and AI rule drafts fill in within a minute.</p>
    <ol class="checks" style="list-style:none">
      <li>Start the stack with Docker Compose.</li>
      <li>Open the console at <code>/app/</code> on port 8080.</li>
      <li>Sign in with the local demo account, then open Alerts and Approvals.</li>
    </ol>
  </div>
  <div class="panel">
    <div class="head">Terminal</div>
    <div class="row"><span>docker compose -f deploy/compose/quickstart.yml up</span></div>
    <div class="row"><span class="k">Console</span><span>http://localhost:8080/app/</span></div>
    <div class="row"><span class="k">Local demo login</span><span>admin@neurawall.local</span></div>
  </div>
</div></section>

<section class="alt"><div class="wrap">
  <h2>Concepts</h2>
  <p class="sub">The ideas the rest of the product is built on.</p>
  <div class="grid">
    {card("Three tiers, one decision", "Tier 1 scores flow behaviour, Tier 2 classifies traffic, Tier 3 (Claude, or an offline advisor) drafts rules. None of them can block. Only the policy engine decides, and every drop maps to a rule id.")}
    {card("What it sees without decrypting", "Flow shape, timing, TLS handshake fields and DNS names. NeuraWall never intercepts TLS and never stores payloads.", "/docs/detection/")}
    {card("Published evasion report", "What the injection detector catches and misses against well-known evasion techniques, case by case. A measurement of one detector, not a detection rate.", "/docs/evasion-report/")}
    {card("Signed bundles", "Every rule change produces an Ed25519-signed bundle. Nodes verify it themselves, refuse older versions and keep the last known good one if the control plane is unreachable.")}
    {card("Safe change management", "Each draft is replayed against recent legitimate traffic. A staged rollout (5%, 25%, all) rolls back automatically if blocking jumps. Optional four-eyes approval.")}
    {card("Audit trail", "A hash-chained record of every change, approval and sign-in that you can verify from the console. It records opaque user ids, never email addresses.")}
    {card("Plans and NEXORA", "One installation links to one NEXORA organisation, and its plan is pulled from NEXORA. A plan change never changes what nodes enforce.", "/pricing/")}
  </div>
</div></section>

<section><div class="wrap">
  <h2>Deploy</h2>
  <p class="sub">Enforcement nodes run the agent next to a flow sensor (Zeek is recommended). They enforce through nftables on Linux, or in dry-run mode to evaluate without touching the host.</p>
  <div class="grid">
    {card("Single host", "Docker Compose with PostgreSQL and automatic HTTPS.")}
    {card("Kubernetes", "A Helm chart: the control plane plus the agent as a DaemonSet.")}
    {card("Bare metal or VM", "systemd units for the control plane and the agent.")}
  </div>
  <p class="note">The deployment guide, configuration reference and operations runbook ship with the product.</p>
</div></section>

<section class="alt"><div class="wrap">
  <h2>Reference</h2>
  <div class="grid">
    {card("REST API", "Interactive OpenAPI documentation, served by your own control plane.", "/api/docs")}
    {card("Configuration", "Settings are environment variables prefixed with NEURAWALL_, with nested sections separated by a double underscore. Setting ANTHROPIC_API_KEY turns on Claude for Tier 3.")}
    {card("Health and metrics", "/healthz and /readyz for probes, and Prometheus metrics at /metrics.")}
  </div>
</div></section>

<section class="dark final"><div class="wrap">
  <h2>Need a hand?</h2>
  <p class="sub">Ask the team, or read the platform documentation.</p>
  <div class="actions"><a class="btn primary" href="mailto:hello@onenexora.com?subject=NeuraWall">Contact us</a><a class="btn line on-dark" href="{DOCS}">NEXORA documentation</a></div>
</div></section>
"""
    return page(
        title="NeuraWall documentation",
        description="Quickstart, concepts, deployment and reference for NeuraWall, the AI-assisted firewall.",
        path="/docs/",
        current="docs",
        body=body,
    )


def detection() -> str:
    body = """
<section class="doc"><div class="wrap">
  <p class="eyebrow"><a href="/docs/">Documentation</a></p>
  <h1>What NeuraWall detects without decrypting.</h1>
  <p class="lede" style="margin-left:0">NeuraWall never decrypts traffic and never stores payloads. It works from flow metadata, so what it can find depends on what the sensor can see.</p>

  <h2>Visible in encrypted traffic</h2>
  <div class="scroll"><table class="compare">
    <thead><tr><th>Signal</th><th>Used by</th><th>What it can find</th></tr></thead>
    <tbody>
      <tr><td>Flow shape: bytes in and out, packet counts, durations, timing</td><td>Tier 1 anomaly engine (Isolation Forest, EWMA baselines)</td><td>A host that suddenly behaves differently, scans, floods</td></tr>
      <tr><td>Inter-arrival timing of one flow</td><td>Beacon detector</td><td>Regular call-backs to a server (C2 beaconing)</td></tr>
      <tr><td>Volume and direction</td><td>Exfiltration detector</td><td>Very large outbound transfers (20 MB and up)</td></tr>
      <tr><td>TLS handshake: SNI, TLS version, JA3 / JA4, ALPN</td><td>TLS mismatch detector</td><td>A client claiming to be a browser with a non-browser fingerprint</td></tr>
      <tr><td>DNS query names</td><td>DNS detector</td><td>DGA-looking names and DNS tunnelling</td></tr>
    </tbody>
  </table></div>

  <h2>Needs the request visible</h2>
  <div class="scroll"><table class="compare">
    <thead><tr><th>Needs the request visible (plain HTTP, or a sensor behind your TLS terminator)</th><th>Used by</th></tr></thead>
    <tbody><tr><td>HTTP path and query</td><td>Injection detector: SQL, command and template injection, path traversal, XSS</td></tr></tbody>
  </table></div>

  <h2>The honest limit</h2>
  <p>On a public HTTPS service the injection detector sees nothing unless the sensor sits behind the TLS terminator, or you already run sensor-side decryption. Tier 1 and the signals in the first table work either way.</p>
  <p>The detectors are heuristics with known gaps, and we publish them: see the <a href="/docs/evasion-report/">Tier 2 evasion report</a>. A detector can only raise an alert; a person approves any rule that blocks.</p>
  <p><a class="btn line" href="/docs/">Back to documentation</a></p>
</div></section>
"""
    return page(
        title="What NeuraWall detects without decrypting · NeuraWall docs",
        description="Which signals NeuraWall uses on encrypted traffic, what needs the request visible, and the honest limits.",
        path="/docs/detection/",
        current="docs",
        body=body,
    )


def evasion_report() -> str:
    title, content = markdown_body((ROOT / "docs/evasion-report.md").read_text())
    body = f"""
<section class="doc"><div class="wrap">
  <p class="eyebrow"><a href="/docs/">Documentation</a> · <a href="/docs/detection/">Detection</a></p>
  <h1>{html.escape(title)}</h1>
{content}
  <p><a class="btn line" href="/docs/detection/">Back to what NeuraWall detects</a></p>
</div></section>
"""
    return page(
        title="Tier 2 evasion report · NeuraWall docs",
        description="What NeuraWall's injection detector catches and misses against known evasion techniques, measured and published.",
        path="/docs/evasion-report/",
        current="docs",
        body=body,
    )


def not_found() -> str:
    body = """
<section class="hero"><div class="wrap">
  <p class="eyebrow">404</p>
  <h1>That page is not here.</h1>
  <p class="lede">The link may be old. Try the product overview, or open the console.</p>
  <div class="actions"><a class="btn primary" href="/">NeuraWall overview</a><a class="btn line" href="/app/">Open the console</a></div>
</div></section>
"""
    return page(
        title="Page not found · NeuraWall",
        description="Page not found.",
        path="/404",
        current="",
        body=body,
    )


FAVICON = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="7" fill="#111821" '
    'stroke="#2b3a49"/><path d="M6 9h20M6 16h20M6 23h20" stroke="#2b3a49" stroke-width="2"/><path d="M11 9v7M21 16v7M16 23v-7" '
    'stroke="#3ddc97" stroke-width="2.4" stroke-linecap="round"/><circle cx="16" cy="16" r="2.6" fill="#3ddc97"/></svg>\n'
)

# Fragment handoff from NEXORA's account app lands on "/", which is now the product site.
# The fragment never reaches a server, so hand it to the console client-side. Kept in an
# external file because the control plane's CSP forbids inline scripts.
SITE_JS = """// Sign in with NEXORA returns to "/#sso_token=...&state=...". The console lives at /app.
(function () {
  if (location.hash.indexOf("#sso_token=") === 0) {
    location.replace("/app/" + location.hash);
  }
})();
"""


def main() -> None:
    SITE.mkdir(parents=True, exist_ok=True)
    (SITE / "pricing").mkdir(exist_ok=True)
    (SITE / "security").mkdir(exist_ok=True)
    (SITE / "docs/detection").mkdir(parents=True, exist_ok=True)
    (SITE / "docs/evasion-report").mkdir(parents=True, exist_ok=True)
    (SITE / "index.html").write_text(home())
    (SITE / "pricing/index.html").write_text(pricing())
    (SITE / "security/index.html").write_text(security())
    (SITE / "docs/index.html").write_text(docs())
    (SITE / "docs/detection/index.html").write_text(detection())
    (SITE / "docs/evasion-report/index.html").write_text(evasion_report())
    (SITE / "404.html").write_text(not_found())
    (SITE / "favicon.svg").write_text(FAVICON)
    (SITE / "site.js").write_text(SITE_JS)
    print(f"wrote {SITE}")


if __name__ == "__main__":
    main()
