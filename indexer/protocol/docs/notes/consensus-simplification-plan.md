# Consensus simplification plan — names-only state machine

**Status:** proposal (2026-07-08). **Cost context: PRE-ACTIVATION, Pepecoin solo
playground.** No names have minted under `ACTIVATION_HEIGHT`, so every change below is a
**free edit** — no migration, no coordinated fork, no historical state to preserve, and the
conformance digest may change freely because nothing depends on the old one. This window
closes at activation; the opcode renumber in particular is *now or never*.

## The principle

> **The namespace state machine tracks names / identity / market. Full stop.** Posts,
> votes, decorations, DNS, DMs are **overlays**. An overlay MAY commit on-chain (permanence
> is a property of the *block*, not of a consensus projection) or gossip off-chain;
> consensus **ignores** every overlay carrier, and each overlay honors its own ops by its
> own rules. The namespace knows nothing about what rides on it.

This is why "users can still post/decorate on-chain" and "remove them from the state
machine" are not in tension: the capability survives (commit an overlay carrier to the
chain and it's permanent), only the *consensus projection* goes away.

## Change 1 — remove VOTE_UP / VOTE_DOWN / DECORATE / text-posts from the SM

All four are content/engagement, not identity. They leave consensus and become overlay
concerns (§"Overlay side" below). What this deletes from the state machine:

- **`0x01` VOTE_UP, `0x02` VOTE_DOWN** — the *only* genesis ops. Their removal collapses
  the entire **genesis-vs-gated two-group split**: every surviving op is gated at one
  `ACTIVATION_HEIGHT`.
- **`0x0B` DECORATE** — removes the SM's *only structural buffer* (`MAX_PEND = 64`,
  `SM_MAX_PEND_DECOR`); the cross-op pending-buffer fold and its divergence-prone clearing
  rules (bind / `AS` / end-of-tx, and the "intervening carrier doesn't flush" subtlety);
  and the "author owns ≥1 name at confirmation height" honor lookup.
- **Text posts** (bare burn-backed UTF-8) — removes the last **content classification** from
  consensus. A valid-UTF-8 `OP_RETURN` no longer becomes a `posts` projection row; it simply
  falls through to *ignore*.

**Projections removed from the digest:** `votes`, `post_decorations`, `posts` (text posts
removed — decided, see below). Smaller digest, simpler conformance.

**Burn checks that remain:** §6's "value field meets the op's requirement" now applies to
**CLAIM / RENEW / RESERVE only** (rent + deposit — core SM). VOTE-weight and text-post
anti-spam burns are gone from consensus; overlays define their own anti-spam.

## Change 2 — simplify the §1 demux

With no text posts, consensus recognizes exactly one shape:

```
byte[0..2] == 0xFF 'P' 'N'  &&  byte[3] ∈ {name-action opcodes}   → name action
everything else (incl. any valid UTF-8, and the whole 0xD6–0xFF overlay band)  → ignore
```

The whole-payload UTF-8 test, the "burn distinguishes an intentional post from ambient
zero-value `OP_RETURN` noise" reasoning, and the noise/post ambiguity all disappear.
Overlay carriers (`0xFF 'P' 'N' 0xD6…0xFF`) already fell through to *ignore* — unchanged.

## Change 3 — renumber name-action opcodes contiguous (0x01–0x0C)

12 ops survive; pack them from `0x01`, order-preserving (minimal semantic diff):

| new | old | action |
|----|----|--------|
| `0x01` | `0x03` | COMMIT |
| `0x02` | `0x04` | CLAIM |
| `0x03` | `0x05` | RENEW |
| `0x04` | `0x06` | TRANSFER |
| `0x05` | `0x07` | SELL |
| `0x06` | `0x08` | RESERVE |
| `0x07` | `0x09` | SETTLE |
| `0x08` | `0x0A` | RELEASE |
| `0x09` | `0x0C` | SELL_TO |
| `0x0A` | `0x0D` | PAY |
| `0x0B` | `0x0E` | AS |
| `0x0C` | `0x0F` | TRADE |

- **Removed:** `0x01` VOTE_UP, `0x02` VOTE_DOWN, `0x0B` DECORATE.
- **Overlay band = the last 200 opcodes `0x38`–`0xFF`** (consensus-ignored; widened from the
  original 42-slot `0xD6`–`0xFF` in the 2026-07-08 standalone-spec polish — "we won't add much to
  the namespace, so give overlays the room"). The specific overlay assignments (`0xD6` label,
  `0xD7` mailbox, `0xD8` DNS) sit inside it unchanged.
- **Future on-chain ops** land in `0x0D`–`0x37` (the gap between the action set and the
  overlay band), preserving the "overlay carrier can never collide with a chain action"
  contract.
- Ordering is defensible-but-adjustable; an alternative is to regroup by concern
  (lifecycle: COMMIT/CLAIM/RENEW/TRANSFER/RELEASE · market: SELL/SELL_TO/PAY/RESERVE/SETTLE
  · identity: AS/TRADE). Order-preserving is the smaller diff; pick one before touching
  impls.

## Change 4 — structural name rules (names are always valid domain labels)

Promote the RFC-1123/IDNA structural rules from "clients MUST flag" to consensus. Charset
stays `[a-z0-9-]`, length 1–32. Add three deterministic checks:

- no **leading** hyphen (`-a` invalid)
- no **trailing** hyphen (`a-` invalid)
- no **`--` in positions 3–4** (`name[2]=='-' && name[3]=='-'`) — the IDNA reserved-label
  rule; kills `xn--` and every future ACE prefix, closing the punycode-homoglyph vector
  **structurally** rather than by client vigilance.

Result: every consensus-valid name is a valid, safe hostname label — the 1:1 name↔domain
mapping becomes total, so DNS/TLS never reject a consensus-valid name as unaddressable.
This finishes the job the `.`/`_` exclusion (2026-07-07) started.

## Overlay side (not consensus — tracked here for completeness)

The removed features already have overlay homes; on-chain forms follow the DNS precedent
(bare prefixed carrier `0xFF 'P' 'N' <op> ‖ …`, ≤80 B relay-settleable, else gossip
off-chain). These are **social-overlay-spec** tasks (a separate layer, not this repo), not consensus:

- **Votes/reactions** → `0xD6` LABEL band (reactions already ride as labels; a vote is a
  label statement, budget/WoT-gated — no per-vote burn).
- **Decorations** → the vpost overlay already carries post decorations (the `board`
  decoration, `post-decorations.md`); assign an overlay-band carrier for the on-chain form.
- **Posts** → an overlay POST carrier (on-chain compact form + the off-chain vpost
  envelope). Consensus-ignored; social honors per its own rules.
- **Author self-deletion (RETRACT)** → moved out of consensus spec §3.8 (collapsed to a
  pointer). Off-chain, no opcode, reuses §4 attribution + the §5 envelope. Preserve the exact
  wire form for the social overlay spec:
  ```
  retract body = "pepenet/v1\nretract\n" ‖ hex(target_txid) ‖ "\n" ‖ target_vout ‖ "\n" ‖ issued_at
  sig          = §5-envelope signature over `body` by the post's §4 vin[0] author
                 (P2PKH: one BIP-137 recoverable sig; P2SH-multisig: m keyset sigs + redeemScript)
  honor iff resolved identity (recovered hash160, or hash160(redeemScript)) == target's recorded §4 author
  ```
  Client-local tombstone keyed `(target_txid, target_vout, author_addr)`, re-validated every
  re-sync (so a retraction whose target a reorg un-indexes stops hiding a now-different outpoint).

## Work breakdown

**A. namespace-protocol (source of truth) — do first.**
1. `docs/protocol-spec.md`: op table (Change 3), demux (Change 2), name validation
   (Change 4), delete §3.8 votes + the DECORATE section (§1) + text-post sections; update
   §6 burn list. `SPEC-RATIONALE.md`, `SPEC-conformance.md`, affected `docs/notes/*`.
2. `impls/c/sm.c` (reference): remove vote/decorate/text-post fold + `votes`/
   `post_decorations`(/`posts`) state + `MAX_PEND` + decorate honor rule; renumber opcodes;
   add name rules. **Regenerate the golden** (`input_digest` + `state_digest`) and re-pin.
3. Port to the other **6 impls** (csharp, go, java, py, rust, ts) — each must reproduce the
   re-pinned golden byte-for-byte via `run-conformance.sh`. This is the bulk of the work;
   the cross-check is the safety net.

**B. namespace-indexer (runtime projection).**
- `src/db.c`: drop the `votes` table (+ `muts`/decorate rows); `src/adapter.h` + engine:
  drop DECORATE body-anchoring; `src/test_chain.c`: drop the VOTE test tx. (The bundled
  wallet CLI has since been removed from the indexer repo — no wallet-side work remains.)
- New opcode constants; new `sm_name_valid` rules. Re-fold clean against pep.db.

**C. Overlay + client consumers (separate repos, tracked there).**
- **Social overlay**: absorb posts/votes/decorate as overlay ops (band assignments +
  on-chain carrier forms + honor rules).
- **Desktop clients**: opcode constants; wallet name gate (fold in the structural
  rules — the p2sh-version gate discussion lives here too); remove on-chain
  vote/decorate UI paths (route to overlay).
- **DNS / TLS / chat layers**: adopt the new name rules — a *simplification*: the
  resolver's apex/label validation can now trust a consensus-valid name IS a valid label
  (drop defensive rejects). Opcode constants if referenced.

## Sequencing

Spec → C reference + re-pinned golden → 6 ports (conformance-gated) → indexer re-fold →
overlays/desktop → dns/tls/chat name-rule adoption. A/B are the load-bearing consensus
work; C is downstream and can lag.

## Decided: text posts REMOVED from the SM (2026-07-08)

Fully names-only. Bare UTF-8 text posts fall through to *ignore*; the entire UTF-8 demux
branch (Change 2) and the `posts` projection are deleted. Posting on-chain still works as an
overlay commit (`0xFF 'P' 'N' <overlay POST op>`, consensus-ignored, honored by the social
overlay) — permanence comes from the block, not from a consensus projection. This is the
cleanest trust root: consensus classifies **no content at all**.
