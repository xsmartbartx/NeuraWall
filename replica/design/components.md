# NeuraWall console: component specs

Source of truth for values: `console/src/tokens.css` (generated from `replica/design/tokens.json` and `tokens.light.json`; both pass WCAG AA with 0 failures, 37 pairs each).
Primitives live in `console/src/components/ui.tsx`; styles in `console/src/styles.css`. There is no Tailwind in the console, so there is no Tailwind mapping: roles are CSS custom properties.
This is the console's own design system, measured rather than copied from another product. Icons: none today (text glyphs only). If icons are added, use an open set (Lucide).

## What changed in this pass (contrast)

| change | before | after | why |
| --- | --- | --- | --- |
| `--text-faint` dark | #5b6c7c, 3.3:1 | #75889a | table headers, hints and nav sections are real text (AA 4.5) |
| `--text-faint` light | #7b8b9a, 3.5:1 | #5e6c7a | same |
| `--border-input` (new role) | inputs used `--border-strong`, about 1.5:1 | dark #4c6781, light #708aa5 | WCAG 1.4.11: a form field's boundary needs 3:1 |
| light `--accent` / `--allow` | #0f9f67, 3.4:1 | #0c7e52 | white text on the primary button and green status text need 4.5 |
| light `--alert`, `--sev-medium`, `--sev-high`, `--info`, `--sev-low`, `--block`, `--sev-critical` | 3.4 to 4.4:1 | darkened until at least 4.5:1 | badges and severity text on white |

Dark theme colours other than `text-faint` already passed and are unchanged.

## Existing components (as built)

```
Button  (button, .btn)
  variants  default, primary, danger, ai, ghost; size small
  states    default, hover, disabled (50% opacity, not-allowed), focus-visible (2px accent outline, 2px offset)
  tokens    bg bg-raised, border border-strong, text text, radius 6; primary = accent / accent-ink
  a11y      real <button>; icon-only buttons need aria-label (Drawer close has one)
  gap       no loading state: busy buttons are only disabled. Add aria-busy and keep the label.
  used on   all
```

```
Field  (input, select, textarea, label.field, label.check)
  states    default, focus-visible, disabled, invalid (not styled today)
  tokens    bg bg-sunken, border border-input (3:1), radius 6, textarea mono 12.5
  a11y      label.field wraps its control; errors are shown as .error-text but not linked with aria-describedby
  gap       add invalid styling (border block) and aria-invalid + aria-describedby
  used on   S01, S02, S06, S10, S14, S16, S17
```

```
Badge  (.badge .c-<kind>)
  kinds     allow/active/approved, alert/pending/rolling_out, block/revoked/rolled_back, quarantine, ai/llm, info/heuristic,
            low/medium/high/critical, offline/superseded (faint)
  tokens    text colour = kind colour, 1px currentColor border, 10% tint
  a11y      colour is never the only signal: every badge carries its text label ("dot" variant adds a dot, not meaning)
  used on   S03-S18
```

```
Card / Kpi
  Card: bg-raised, 1px border, radius 8, optional header with actions, `pad=false` for tables
  Kpi:  label 12 muted, value 26 mono, tone variants (block, alert, ai)
  used on   S03, S17, S18
```

```
Table
  states    loading (Loading), empty (Empty), filled, clickable row (hover bg-hover), selected row (inset accent bar)
  tokens    th 11.5/600 uppercase text-faint, td 8x12 padding, num columns right-aligned mono
  a11y      clickable rows must also be reachable by keyboard: today they are mouse-only
  gap       add tabindex=0 + Enter/Space on rows that open a drawer; add scope="col" on th
  used on   S04, S06, S08, S11, S13, S14, S15, S16
```

```
Drawer / Modal
  Drawer: right side, min(640px, 100vw), role=dialog aria-modal, close button aria-label
  Modal:  min(560px, 100%), footer actions right-aligned, backdrop click closes
  gap       focus is not trapped or returned to the trigger; Escape handling to confirm
  used on   Drawer: S05, S07, S09, S12   Modal: S10, S12, S13, S14, S16
```

```
Meter       8px bar, warn turns block colour at >= 100%; needs role=progressbar + aria-valuenow (gap)   used on S17
Callout     left border 3px: info (default), ai, warn, danger                                         used on S09, S17, S18
Toast       bottom-right, 3px left bar (accent / block for error), no auto role; add role=status      used on all
Loading     spinner 16px + label                                                                       used on all
Empty       centered muted message                                                                     used on all lists
Layout      224px sidebar, sticky topbar, page max 1480, mobile drawer nav below 860px                  used on all
Charts      SVG, tooltip on hover; add a visually hidden table or aria-label summary (gap)             used on S03
Theme       dark default, light via localStorage "neurawall.theme"
```

## New components for the integration work (specs; built in /replica-build)

```
Toggle  (switch)
  use       enable/disable a notification channel; "Allow password login" setting
  anatomy   <button role="switch" aria-checked> + visible label; 36x20 track, 16 knob
  states    off, on, hover, focus-visible, disabled, busy
  tokens    off: border-input, bg-sunken. on: accent track, accent-ink knob. radius pill
  a11y      Space/Enter toggles; the label is the accessible name; state is not colour-only (knob position + aria-checked)
  used on   S23 Integrations, S18 Settings
```

```
SecretReveal
  use       shows a signing secret / API key once, right after creation
  anatomy   callout (warn) + mono value in pre.code + Copy button + "I have stored it" confirm to close
  states    hidden (never shown again), revealed, copied (toast "Copied")
  tokens    pre.code, callout.warn
  a11y      Copy button announces result via role=status; value is selectable text, not an image
  rule      value is never written to the console URL, logs or localStorage
  used on   S23 (webhook secret)
```

```
StatusPill  (link and sync state)
  kinds     linked (allow), grace (alert, "Using last known plan, N days left"), unlinked (faint), error (block)
  tokens    reuses Badge kinds; the text always states the state
  used on   S17 billing header, S18 settings, S23
```

```
BudgetMeter
  use       Claude calls this period vs the plan budget (Business, Enterprise); Pro shows "Your own Anthropic key"
  anatomy   Meter + "812 / 3,000 calls · resets 1 Nov" + Callout when over: "Using the offline advisor until the period resets"
  states    under, near (>= 80%, alert), over (block), unlimited (no meter), not applicable
  a11y      Meter gets role=progressbar, aria-valuenow, aria-valuemax
  used on   S17, S18
```

```
ChannelRow / ChannelForm  (notification channels)
  fields    name, https URL, events (checkbox group), minimum severity (select), active (Toggle)
  validation  URL must be https and a public address; error text linked by aria-describedby, input aria-invalid
  actions   Send test, Rotate secret, Delete (danger, confirm Modal)
  states    never delivered, last delivery ok, last delivery failed (http status), dead (stopped after retries)
  used on   S23
```

```
SsoButton  ("Sign in with NEXORA")  already built; add:
  states    default, redirecting (disabled, aria-busy), refused (shows the same generic message as a failed password)
  rule      copy never says whether the email, the organisation or the token was the reason
  used on   S01
```

```
ExportButton
  use       "Export CSV" on Flows, Alerts, Audit
  states    default, preparing (busy), capped (callout: "First 50,000 rows exported. Narrow the filters for the rest.")
  used on   S04, S06, S15
```

New screen: **S23 Integrations** (`/integrations`, admin): NEXORA link status (StatusPill, org id, last sync, "Sync now"), notification channels list, deliveries table.

## Keyboard and screen reader checklist (applies to every new component)

- Everything reachable and operable by keyboard; visible focus ring (the global `:focus-visible` rule already gives 2px accent).
- Dialogs: trap focus, Escape closes, focus returns to the trigger.
- Status changes announced with `role="status"` (toasts, sync result, copy confirmation).
- Colour is never the only carrier of meaning (state words on every badge and pill).
- Targets at least 24x24 CSS px (WCAG 2.2 AA); `button.small` is currently about 24px high, so no smaller.
