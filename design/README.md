# Handoff: pepenet — .pepe name manager (visual system + core screens)

## Overview
pepenet is a desktop client for managing `.pepe` blockchain names: discovering live `.pepe` sites, managing owned names, editing DNS records, issuing/pinning SSL certificates, and a first-run consent prompt. This bundle contains the visual system reference (1a) and eight high-fidelity screens (9a–9h).

## About the Design Files
The files in this bundle are **design references created in HTML** — prototypes showing intended look and behavior, not production code to copy directly. The task is to **recreate these designs in the target codebase's existing environment** (React, native, Electron, etc.) using its established patterns and libraries — or, if no environment exists yet, choose the most appropriate framework and implement the designs there. The mocks are drawn flat (no shadows, no gradients) and are intentionally renderable in immediate-mode UI toolkits (e.g. Nuklear) as well as the web.

## Fidelity
**High-fidelity.** Colors, typography, spacing, radii, and copy are final. Recreate pixel-perfectly. All styles are inline in `screens.html` — inspect any element for exact values.

## Screens / Views
All app screens are 920×660, window chrome included (traffic lights, centered "pepenet" title, tab strip: Discover / My Names / Name Market + wallet balance chip). A status footer shows daemon state + `synced · <block height>`.

- **1a — Visual system**: palette swatches, type scale, and shape/button specimens. Use as the token source of truth.
- **9a — Discover**: search bar + card grid of `.pepe` sites. Card art is a generated identicon (3×3 colored grid), not a site fetch. Description comes from the owner's `_site` TXT record, clamped to 2 lines. States: normal, name-only (no TXT), lapsed (LAPSED badge, desaturated), info-only. Green dot top-right of art = servable.
- **9b — My Names**: row list of owned names. Per-row: identicon, name, expiry countdown (text fades in 4 steps as expiry nears), status badge (OWNED filled / OFFERED bordered / LIVE filled), row actions. A queued op temporarily swaps the badge and disables that row's actions. Sticky bottom bar carries Renew / Transfer for the selection.
- **9c — DNS (per-name)**: record table (TYPE / HOST / VALUE / TTL). Edit = overwrite; delete lives inside the edit modal. `_443._tcp TLSA` row is greyed and system-managed. `_site` TXT feeds the Discover card.
- **9d — SSL (per-name)**: a certificate **list**, not a single cert. Default apex entry (`gm.pepe` + `*.gm.pepe`) plus per-subdomain entries, each with its own key. Pin states: ✓ pinned (green strip), ! not pinned yet (accent-green strip + `publish pin` button), ✕ mismatch (red).
- **9e — SSL empty state**: no cert yet; the Create panel is the page focus, Active panel shows a dashed placeholder.
- **9f — Add record modal**: centered over dimmed DNS page. Type / host / value / TTL, live PREVIEW dry-run row, inline VALUE validation error, passive over-80-byte hint, SRV tucked under "more…".
- **9g — Edit record modal**: same modal pre-filled. Edit = overwrite (latest wins). Delete = publish empty record; destructive action sits bottom-left.
- **9h — First-run consent**: single admin prompt. Scope promise (`.pepe` ONLY), what it installs (root cert · resolver · port redirect), "skip for now" path.

Exact layout, copy, and per-component values: see the matching section in `screens.html`.

## Interactions & Behavior
- Tabs: active tab has a 2px `#77C25B` underline; inactive tabs are `#9FA887` text.
- Hover: background steps up one level (`#21231B → #292C21 → #313526`). Pressed: border turns `#77C25B`. No shadows or transitions beyond these.
- Filled-green buttons **spend money**; bordered buttons are safe. Keep this rule absolute.
- Queued blockchain ops (~1 min confirm) disable the affected row's actions and show a temporary badge until settled.
- Modals dim the page beneath (`rgba(14,15,12,0.55)`).
- Expiry fade: name text steps `#E9EFD8 → #9FA887 → #767D63 → #515742` as expiry approaches.

## State Management
- Per-name: expiry countdown, status (owned / offered / live / lapsed / reserved), queued-op flag, DNS record set, cert list with per-entry pin state (pinned / unpinned / mismatch).
- Global: wallet balance, daemon sync state + block height, resolver health (footer warning when degraded).
- Discover cards derive art from the name (identicon hash) and description from the `_site` TXT record — no site fetching.

## Design Tokens
Colors (swamp-dark, flat only — no shadows, no gradients):
- `#191A16` bg · `#21231B` panel · `#292C21` input/hover · `#313526` pressed-hover step · `#363A2C` 1px borders
- `#E9EFD8` text · `#9FA887` text dim · `#767D63` text faded · `#515742` text ghost
- `#77C25B` accent green (primary actions, active tab, engrave) · `#9CB856` olive = ok/status · `#D97757` red = danger/lapsed
- Tinted strips: green `rgba(156,184,86,.10)` on `#4A5C39` border; accent `rgba(119,194,91,.09)` on `#4D6B39` border; red `rgba(217,119,87,.10)` on `#6B4A3E` border
- Window traffic lights: `#FF5F57` `#FEBC2E` `#28C840`; identicon content colors: `#7FA9D6` blue, `#B98AD0` purple, `#C58F6A` tan

Typography:
- **Patrick Hand** (voice): 30px titles, 19px body/labels/buttons. Never touches a number that matters.
- **Space Mono** (truth): 14px data, 11px meta, 10px badges/labels. Anything a user could lose money misreading — amounts, addresses, hashes, countdowns, byte counts — is ALWAYS Space Mono.

Spacing: 4 / 8 / 12 / 16 / 24. Radii: 6 (buttons, chips) / 10 (cards, panels); 4 for small badges, 8–9 for strips/modals. No shadows.

## Assets
None. All art (identicons, dots, swatches) is drawn with plain colored divs. Fonts are Google Fonts: Patrick Hand, Space Mono.

## Files
- `screens.html` — self-contained reference: visual system (1a) + screens 9a–9h, all styles inline. Open in any browser.
