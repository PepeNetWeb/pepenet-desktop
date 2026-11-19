# Consensus-simplification — surgical edit sites

> **STATUS (2026-07-08): SPEC EDITS APPLIED + ADVERSARIALLY VERIFIED.** All four docs edited
> (protocol-spec.md, SPEC-RATIONALE.md, SPEC-conformance.md, README.md). 5-lens adversarial
> verify passed clean (one MINOR leftover — a dangling "weight" in RATIONALE §10.4 — fixed).
> §3.8 collapsed to an overlay pointer; RETRACT wire form relocated to
> `consensus-simplification-plan.md` §"Overlay side". Golden HEX values intentionally NOT
> edited (D4) — they regenerate from the re-pinned C reference in the impl phase (work-item A.2+).

Execution reference for the names-only SM change (see `consensus-simplification-plan.md` for
the why). Pre-activation, all edits free. Produced by an exhaustive 6-dimension mapping sweep
(VOTE / DECORATE / TEXT-POST / OPCODES+DEMUX+GENESIS / NAME-RULES / DIGEST+BURN) + synthesis.

## Renumber key

Apply **by semantic context only** — never blanket find/replace (hex 0x01–0x07 also appear as
SIGHASH_ALL, pubkey prefixes, bitmap flags, comma 0x2C, push opcodes).

```
COMMIT 0x03→0x01 · CLAIM 0x04→0x02 · RENEW 0x05→0x03 · TRANSFER 0x06→0x04 · SELL 0x07→0x05
RESERVE 0x08→0x06 · SETTLE 0x09→0x07 · RELEASE 0x0A→0x08 · SELL_TO 0x0C→0x09 · PAY 0x0D→0x0A
AS 0x0E→0x0B · TRADE 0x0F→0x0C
REMOVED: VOTE_UP 0x01, VOTE_DOWN 0x02, DECORATE 0x0B
Opcode range 0x01..0x0F → 0x01..0x0C · Overlay band 0xD6–0xFF UNCHANGED · Future on-chain 0x0D–0xD5
```

## Resolved decisions (do not re-litigate)

- **D1 overflow_flag** → DROP entirely wherever it appears (conf §4 digest block, §8
  fingerprint/invariants, §13.2 top-hash, RATIONALE §7.7/§10.1). No "pinned to 0" — remove it.
- **D2 digest magic** → bump `"SMv1"`→`"SMv2"` (conf §4 + any other "SMv1" ref).
- **D3 §3.8** → do NOT delete the section. Retitle to drop "votes" (e.g. `### 3.8 Author
  self-deletion (off-chain RETRACT) & off-chain reactions`); delete the VOTE_UP/VOTE_DOWN
  paragraph + its 0x01/0x02/min-weight/§5-value-check content; KEEP RETRACT + reactions,
  framed as off-chain/overlay, not consensus. Keep the §3.8 number.
- **D4 golden hashes** → do NOT hand-edit any hex golden (they regenerate from the re-pinned C
  reference in the impl phase). Instead (a) add a banner at the TOP of SPEC-conformance.md:
  `> ⚠ GOLDENS STALE (names-only consensus simplification, 2026-07-08): every frozen digest
  below is pending regeneration from the re-pinned C reference — see
  docs/notes/consensus-simplification-plan.md.` and (b) edit all STRUCTURAL descriptions around
  the goldens (sub-accumulator counts, tag lists, fingerprint field lists, vector enumerations,
  generator op-weight arrays).
- **D5 RATIONALE §7** → after deleting §7.4 and §7.7, LEAVE the numbering gaps (no renumber
  cascade); add `(§7.4 and §7.7 removed in the names-only simplification.)` at the §7 top; drop
  the closing-paragraph "32-byte synthetic post-id" hardening citation.
- **D6 conf §5 generator** → KEEP `activation_height=0` (all-active harness). No change.
- **D7 conf §7 vectors** → remove the deleted vectors' descriptions (vote scoring/i128,
  DECORATE gate/orphan, 53_decor_pend_cap); rewrite the 52_charset vector desc for the new
  structural name rules; do NOT fabricate a new total or renumber the battery here — add
  `(battery renumbered + combined golden re-pinned during the impl update)`. Keep README/conf
  counts consistent by NOT asserting a specific stale number.
- **D8 opcode order** → order-preserving per the key above.
- **D9 pre-existing** → do NOT touch the §3.10 TRADE "length 1..20" vs §3.1 "1..32" discrepancy
  (out of scope; flag only).

## Collision guards — do NOT renumber these (not action opcodes)

- SIGHASH_ALL `0x01` and the 4-byte hashtype `0x01 0x00 0x00 0x00` (§4).
- Pubkey prefixes `0x02`/`0x03` (compressed), `0x04` (uncompressed), `0x06`/`0x07` (hybrid);
  push-opcode lengths `0x21`/`0x47`/`0x48` (§4).
- TRADE pair separator comma `0x2C`.
- Framing bytes `0xFF`/`0x50`/`0x4E` ('PN' prefix).
Only renumber a hex byte that is unambiguously an ACTION OPCODE by semantic context.

---

# Per-file edit list

Execute each file **bottom-to-top** (listed in that order) so earlier deletions never move
later locators. `[NAME-RULES]`/`[POST]` mark sites backfilled from direct reads (verify hardest).

## FILE 1 (PRIMARY): docs/protocol-spec.md

- **§6 size budget — L1588** · `| DECORATE | 4 + Σ records ≤ 80 | ✅` · DELETE the DECORATE row.
- **§6 size budget — L1579** · `| VOTE_UP / VOTE_DOWN | 40 | ✅ |` · DELETE the VOTE row (survivors name-keyed, no renumber).
- **§5 fold-vectors — L1562-1563** · `AS flushing the pending DECORATE buffer` · drop that clause; keep segment/vin[k]/anon-post-drop desc.
- **§5 fold-vectors — L1555-1557** · `the **DECORATE** binding (TLV framing fail-closed on overrun` · DELETE whole DECORATE-binding item incl. the §1 name-ownership honor-rule vector.
- **§5 fold pseudocode — L1471** · `post_decorations (records bound to a post's (txid,vout)` · DELETE the post_decorations sentence.
- **§5 fold pseudocode — L1463** · `**Tables.** votes (per (target,vout)` · DELETE the votes sentence; keep names/commits/last_set_mutation_height.
- **§5 fold pseudocode — L1460** · `any pending DECORATE records with no following body → orphan` · DELETE the orphan comment line.
- **§5 fold pseudocode — L1458** · `elif o.value > 0 and len(payload) >= 1 and valid_utf8(payload):  text post` · DELETE the entire text-post elif branch (author + DECORATE-bind + honor + clear-buffer).
- **§5 fold pseudocode — L1457** · `# DECORATE: split into [tag][len:2][value] records` · DELETE the DECORATE dispatch comment.
- **§5 fold pseudocode — L1447** · `for burn-bearing ops … VOTE: value ≥ DUST_FLOOR;` · REWRITE → CLAIM/RENEW (T≥1 water-fill §3.5) + RESERVE (value ≥ burn_leg §3.7) only.
- **§5 fold pseudocode — L1443** · `if opcode == TRADE (0x0F):` · RENUMBER 0x0F→0x0C (leave 0x2C comma note L1456).
- **§5 fold pseudocode — L1439-1440** · `if opcode == AS (0x0E):` / `k = payload[4]; flush any pending DECORATE buffer` · RENUMBER AS 0x0E→0x0B and drop the flush clause.
- **§5 fold pseudocode — L1438** · `if opcode in 0x03..0x0F and height < ACTIVATION_HEIGHT: drop` · REWRITE → `if height < ACTIVATION_HEIGHT: drop; continue` (all ops gate at one height).
- **§5 fold pseudocode — L1437** · `elif payload starts with 0xFF 'P' 'N' + opcode in 0x01..0x0F:` · RENUMBER range 0x01..0x0F→0x01..0x0C.
- **§5 fold pseudocode — L1430** · `The scan extends the existing valid_utf8() demux:` · REWRITE → drop valid_utf8(); "the fold scans each single-push OP_RETURN in vout order".
- **§5 web-of-trust — L1360-1363** · `Votes are anonymous (WoT filters by address, and only while an indexer still keeps per-voter rows)` · REWRITE: votes now off-chain overlay; drop the per-voter-rows clause; fold votes into off-chain social signals w/ reactions.
- **§5 identity display — L1368** · `ASCII confusables survive the charset rules` · REVIEW [NAME-RULES]: keep (ASCII 0/o,1/l,rn/m survive) but ensure it no longer implies xn--/leading-hyphen names are valid (Change 4 kills them).
- **§4 conformance summary — L1348** · `the §1 strict-UTF-8 demux, and (Rule 1b)` · DELETE `the §1 strict-UTF-8 demux, ` [POST].
- **§4 O(1) note — L1343** · `individual posts/votes stay one verify` · REWRITE → `individual actions stay one verify`.
- **§4 Rules 3/4 & step-by-step — L1228,1268,1273,1283-1285,1298,1301,1319,1323,1327,1335** · SIGHASH_ALL 0x01 / hashtype / pubkey-prefix / push-op · REVIEW ONLY — DO NOT renumber (collision guard).
- **§4 authority — L1262** · `and **official posts/votes** — is the native n-of-m spend` · REWRITE → `official name actions`.
- **§4 Rule 2 — L1220** · `owned by, and **post/vote as**, an n-of-m group` · REWRITE → `owned by, and act as, an n-of-m group`.
- **§4 Rule 1b — L1203** · `its segment's actions **drop** (a bare post → **anonymous**)` · REWRITE [POST] → drop the anonymous-post parenthetical.
- **§4 Rule 1b — L1193** · `An **AS k** carrier (0x0E) re-points it to vin[k]` · RENUMBER AS 0x0E→0x0B.
- **§4 Rule 1 — L1186-1190** · `This applies to **text posts** too: a post's author is its §4-verified vin[0]` · REWRITE [POST]: remove the text-post attribution passage through `… anonymous content — no address, not retractable.`; keep the vin[0]-identity/funding-only lines.
- **§3.10 TRADE — L1110** · `**TRADE (0x0F)** — atomic 1-1 name swap.` · RENUMBER 0x0F→0x0C (leave 0x2C L1112).
- **§3.10 AS composition — L1106** · `a bare post → **anonymous**` · REVIEW [POST]: reword/drop the bare-post outcome; keep OOB/failed-AS drop rule.
- **§3.10 AS composition — L1104** · `AS flushes the pending DECORATE buffer (a post and its decorations` · DELETE the sentence; keep OOB/§4-fail-drop + orphan-AS-no-op + re-AS-resets.
- **§3.10 AS use — L1095** · `A custodian batches M users' votes/posts/renews into one tx` · REWRITE → `batches M users' renews/transfers into one tx, each AS-segmented to its owner`.
- **§3.10 AS heading — L1081** · `**AS (0x0E)** — the acting identity.` · RENUMBER AS 0x0E→0x0B.
- **§3.9 storage — L1043** · `Vote rows are additively sheddable (the floor is a min-burn filter, one layer up).` · DELETE the sentence.
- **§3.9 determinism table — L1019** · `| votes | a subjective per-user view | **client policy**` · DELETE the votes row; keep identity+market+attribution + RETRACT rows.
- **§3.8 Engagement — L971-1008** · heading `### 3.8 Engagement — votes; …RETRACT` + `**VOTE_UP (0x01) / VOTE_DOWN (0x02)**` · per D3: retitle (drop votes), DELETE the VOTE paragraph (L973-983), KEEP RETRACT (L985-1005) + reactions (L1007) as off-chain.
- **§3.7 PAY — L920** · `**PAY (0x0D)**` · RENUMBER 0x0D→0x0A.
- **§3.7 SELL_TO — L903** · `**SELL_TO (0x0C)**` · RENUMBER 0x0C→0x09.
- **§3.7 SETTLE — L859** · `**SETTLE (0x09)**` · RENUMBER 0x09→0x07.
- **§3.7 RESERVE — L811** · `**RESERVE (0x08)**` · RENUMBER 0x08→0x06.
- **§3.7 SELL — L770** · `**SELL (0x07)**` · RENUMBER 0x07→0x05.
- **§3.6 RELEASE — L728** · `**RELEASE (0x0A)**` · RENUMBER 0x0A→0x08.
- **§3.6 heading — L705** · `### 3.6 TRANSFER (0x06) & RELEASE (0x0A)` · RENUMBER 0x06→0x04 & 0x0A→0x08.
- **§3.5 TRANSFER form — L701-702** · `[0xFF PN 0x06][target:20]` · RENUMBER 0x06→0x04 (both all-form + selective).
- **§3.5 RENEW wire — L625-627, L636** · `RENEW all [0xFF PN 0x05]` (+ variants + `the 4-byte 0xFF PN 0x05 prefix`) · RENUMBER 0x05→0x03 (all four).
- **§3.5 batching — L551-555** · `The one pinned structural bound is the DECORATE pending-record cap MAX_PEND` · REWRITE: delete the MAX_PEND carve-out → now zero below-block structural cap.
- **§3.2 CLAIM — L357** · `**CLAIM (0x04)**` · RENUMBER 0x04→0x02.
- **§3.2 COMMIT — L325** · `**COMMIT (0x03)**` · RENUMBER 0x03→0x01.
- **§3.1 name validation — L279-306** · `length 1–32 bytes, no structural rules.` / `Consensus keeps "no structural rules"` / `clients MUST refuse or flag any name whose label begins xn--` · REWRITE/ADD [NAME-RULES] (Change 4): (a) replace `no structural rules` with the three consensus checks — no leading hyphen, no trailing hyphen, no `--` at positions 3-4 (`name[2]=='-' && name[3]=='-'`, kills xn-- + all IDNA ACE); (b) rewrite L291-306 so consensus NOW enforces RFC-1123 positioning (`-a`, `a-`, `xn--…` are invalid names, dropped at consensus), soften the client-MUST-flag guidance (now structural), state every consensus-valid name is a valid safe domain label (1:1 total). Keep reject-not-fold / lowercase / ASCII-confusable framing.
- **§3.0 activation — L242-249** · `Posts and votes are **ungated** (live from genesis)` + `Everything else — COMMIT/CLAIM, … and DECORATE` · REWRITE: delete the ungated-posts/votes paragraph (L242-245); drop `Everything else —` contrast + `and DECORATE`; all ops activate atomically at the single ACTIVATION_HEIGHT (keep forward-only + blind-commit text).
- **§2 overlay band — L225-234** · `outside 0x01–0x0F` / `assigned in 0x10–0xD5` / `so it can never be a post either` · REWRITE: keep 0xD6–0xFF contract; `0x01–0x0F`→`0x01–0x0C`, `0x10–0xD5`→`0x0D–0xD5`, drop the `never be a post` UTF-8 aside.
- **§2 registry table — L205-223** · Genesis/Gated header rows + VOTE_UP/VOTE_DOWN/DECORATE rows · REWRITE: delete both group headers + the three removed rows; ONE group; RENUMBER survivors per key; optional `live at ACTIVATION_HEIGHT` caption.
- **§2 registry intro — L198-202** · `Fifteen opcodes in **two groups**. Genesis ops (0x01–0x02)` · REWRITE: `Fifteen`→`Twelve`; drop two-group framing; all at one ACTIVATION_HEIGHT; RENUMBER inline SELL_TO/PAY/AS/TRADE; delete the `plus 0x0B DECORATE` clause.
- **§1 decorated posts — L149-192** · `**Decorated posts (a layered extension).**` · DELETE the entire subsection (0x0B label, TLV grammar, MAX_PEND=64/SM_MAX_PEND_DECOR + "single structural cap", orphan-drop, three-clearing-rules incl. L180 VOTE example + L188 votes/reactions analogy, L185 post_decorations digest note, L189-191 honor rule, activation clause). Verify the `---` at L194 stays the §1/§2 separator.
- **§1 text posts — L137-148** · `**Text posts** carry no prefix: a burn-backed OP_RETURN` · DELETE both paragraphs (whole-payload UTF-8, RFC-3629, burn-vs-noise, zero-value-falls-to-ignore) [POST]/DEMUX.
- **§1 single-minimal-push — L125-135** · `the bytes both the prefix test above and the UTF-8 demux below read` · REWRITE: keep lone-minimal-push carrier (P≤80, one minimal push else ignore, batching); strip UTF-8/text-post refs (`the UTF-8 demux below`→`the prefix test`; `(it is neither an action nor a text post)`→`(it is not a protocol action)`; drop `and the whole-payload UTF-8 test (§5)`).
- **§1 header table — L123** · `| 3 | [opcode] | 1 byte, 0x01–0x0F |` · RENUMBER range 0x01–0x0F→0x01–0x0C.
- **§1 framing intro — L114-116** · `indexers separate actions from plain text posts with no content heuristics` · REVIEW/REWRITE [POST] → `separate actions from all non-action carriers (overlay band + any UTF-8), which fall through to ignore`.
- **§0 constants MAX_PEND — L91** · `MAX_PEND (SM_MAX_PEND_DECOR) | 64 records | max DECORATE records buffered` · DELETE the whole row.
- **§0 constants DUST_FLOOR — L75** · `also the minimum vote weight (§3.8), the RESERVE deposit-leg floor` · REWRITE: delete `the minimum vote weight (§3.8), ` (keep rent-clamp + RESERVE + SELL-basis).
- **§0 foundations (burn) — L32-34** · `in three places: a **vote weight** (§3.8), name **rent**` · REWRITE: `three`→`two`; delete the vote-weight item (keep rent + reserve deposit).
- **Intro — L11-14** · `everything social, advisory, or price-finding (reactions,` · REVIEW: optionally add votes/posts/decorations to the off-chain enumeration.
- **Intro — L3-4** · `an identity + engagement layer carried in Dogecoin` · REWRITE: drop "engagement" → `an identity + naming/market layer carried in Dogecoin OP_RETURN actions.`

## FILE 2: SPEC-RATIONALE.md

- **§10.6 — L497 & L500** · `…decoder, TLV parser,` / `TLV lengths` · REWRITE: remove `, TLV parser` and `TLV lengths` (TLV only existed for DECORATE); keep decoder/attribution-cursor guidance.
- **§10.5 — L488-492** · `votes by (target,vout); mutations by owner; decorations by (txid,vout) *stably*` · REWRITE: remove votes + decorations sort keys; delete the `Decorations need a stable sort (C# List.Sort…)` sentence; keep names/commits/mutations.
- **§10.1 — L461-466** · `The vote accumulator is signed 128-bit and *fail-loud* on overflow (set the digest overflow byte)` · REWRITE: delete the vote-accumulator sentence + `two's-complement {hi,lo} accumulator`; keep deposit-leg/lease-numerator 128-bit; per D1 remove all "set the digest overflow byte" language.
- **§8.7 — L426-428** · `**8.7 POST is never gated and never dropped**` · DELETE the whole subsection [POST].
- **§8.6 — L415-424** · `**8.6 Decoration binding, ownership gate, orphan cleanup.**` · DELETE the whole subsection (incl. `Votes/decorations key on txid`).
- **§8.5 — L408-413** · `A value = 0 VOTE decodes to an ACTION…is dropped` · REWRITE: remove the value=0 VOTE + zero-value-UTF-8-IGNORE [POST] + per-op VOTE clause + the DECORATE-buffer-flush trailing sentence; keep CLAIM/RENEW water-fill + RESERVE value ≥ burn_leg.
- **§8.4 — L404** · `DECORATE [0,76] (bl=0 is a valid record-less` · REWRITE: delete the DECORATE band; keep RENEW/TRANSFER/TRADE bands.
- **§8.3 — L395-398** · `**8.3 Strict RFC-3629 UTF-8 over the whole payload.**` · DELETE the whole subsection [POST]/DEMUX.
- **§8.2 — L390-393** · `**8.2 Name charset is reject-not-fold.** [a-z0-9-]…length 1–32` · REWRITE/ADD [NAME-RULES]: extend reject-not-fold to the three structural rejects (leading `-`, trailing `-`, `--` at pos 3-4) → `-a`/`a-`/`xn--…` = whole-action IGNORE; update the "supersedes scenario 52" pointer.
- **§8.1 — L385** · `An empty push (OP_0/P=0) can't carry the 4-byte prefix nor a len≥1 post → ignore.` · REWRITE [POST]: drop `nor a len≥1 post`.
- **§7.8 — L374-377** · `i128 scores are 16-byte LE two's-complement.` · REWRITE: remove the i128-score sentence; keep i64/u64 signedness for lease/offer/reserve/commit + price/legs.
- **§7.7 — L365-372** · `**7.7 Votes store net score; synthetic post-id is 32 bytes.**` · DELETE the whole subsection (per D5 leave the §7.7 number gap).
- **§7.4 — L348-354** · `**7.4 Decoration rows: one per record, verbatim TLV…**` · DELETE the whole subsection (per D5 leave the §7.4 number gap).
- **§7 top** · ADD note per D5: `(§7.4 and §7.7 removed in the names-only simplification.)`; drop the closing-paragraph 32-byte-synthetic-post-id citation.
- **§4.3 — L208 (heading) & L213-218 (body)** · `**4.3 AS re-points attribution only; the ⊥-actor rule; buffer flushing.**` / `*Buffer:* exactly three things clear the pending DECORATE buffer` · REWRITE: drop `; buffer flushing` from heading; delete the buffer body (incl. `TRADE/VOTE/COMMIT/SELL between a DECORATE and its body is non-flushing`); keep AS attribution/⊥-actor.

## FILE 3: SPEC-conformance.md  (per D4: DO NOT hand-edit hex goldens; add stale banner; edit structure only)

- **TOP OF FILE** · ADD the D4 goldens-stale banner.
- **§13.2 ECMH empty-state — L775-778** · `all five sub-accumulators ∞` / `empty_state_ecmh = 053f61e5…` · REWRITE `five`→`three`; the hash regenerates (leave value, banner covers it).
- **§13.2 ECMH combined — L771** · `combined = 2cdee6ada7…` · leave value (regen).
- **§13.2 ECMH tags/top-hash — L758-761** · `names=01 commits=02 votes=03 muts=04 decors=05` / `Five sub-accumulators` / `SHA256("ECMHtop1" ‖ A_names ‖ A_commits ‖ A_votes ‖ A_muts ‖ A_decors ‖ overflow_flag)` · REWRITE: retag `names=01 commits=02 muts=03`; `Five`→`Three`; drop `A_votes ‖`, `A_decors ‖`, and `‖ overflow_flag` (D1).
- **§12 self-checks — L562 & L556** · `except the unreachable vote_overflow` / `+ UTF-8 demux/fail-closed drop cases` · REWRITE: remove the vote_overflow branch clause; trim `UTF-8 demux/` [POST].
- **§11 meta inert-tx — L540 & golden L545** · `a zero-weight VOTE, a malformed-decoded IGNORE carrier, an orphan DECORATE, a zero-value POST` · REWRITE: drop the VOTE/orphan-DECORATE/zero-value-POST probes → e.g. `a malformed-decoded IGNORE carrier + an overlay-band carrier`; leave the L545 golden value (regen).
- **§10 reorg golden — L522** · leave value (regen).
- **§9 bfuzz goldens — L495-497** · leave values (regen).
- **§9 fuzz goldens — L478-480** · leave values (regen).
- **§9 fuzz draw order — L469,472,473** · `1+bnd(15)` opcode / `bnd(21)` opcode · REWRITE: `1+bnd(15)`→`1+bnd(12)`; REVIEW the `bnd(21)` boundary constant vs the new valid/overlay edge.
- **§9 per-opcode decode — L463-464** · `TRADE bl≥5 …both names §3.1` / `Names validate per §3.1 ([a-z0-9-],1..32; re-pinned 2026-07-07)` · ADD [NAME-RULES]: note names also reject leading/trailing hyphen + `--` at pos 3-4.
- **§9 per-opcode decode — L461** · `DECORATE bl 0..80 (SM_DEC_MAX; raw TLV…` · DELETE the DECORATE decode band (removes SM_DEC_MAX + vector 53 ref).
- **§9 per-opcode decode — L457** · `VOTE_* bl==36 (txid32+vout4) · COMMIT bl==32` · DELETE the `VOTE_* bl==36 · ` entry; survivors map 0x01..0x0C.
- **§9 sm_decode_payload — L448-454** · `sm_decode_payload(...) → ACTION | POST | IGNORE` / `POST iff (not an action prefix) and value>0` · REWRITE: collapse to `ACTION | IGNORE`; delete the POST branch (whole-payload sm_valid_utf8 + "post bytes capped at 80"); ACTION opcode set 0x01..0x0C; trim the `0xFF lead is never valid UTF-8` aside.
- **§9 decode coverage — L446** · `decode coverage (ignore / post / per-opcode-action)` · REWRITE: drop `post` bucket [POST].
- **§8 property golden — L433** · leave value (regen).
- **§8 property fingerprint — L428-429** · `i128 Σ vote.score …16 bytes LE` / `u8 overflow_flag` · DELETE the Σ vote.score line; DELETE overflow_flag (D1).
- **§8 property fingerprint — L424** · `u32 n_commits, n_votes, n_muts, n_decors` · REWRITE → `u32 n_commits, n_muts`.
- **§8 invariants — L418** · `every mutation height ≤ cur_height; overflow == 0.` · REWRITE: remove `overflow == 0` (D1); keep DUST_FLOOR/market invariants.
- **§7 golden history — L391** · `combined = 4c84238f…; 53_decor_pend_cap + 54_no_txcap]; db714fa4… the 52-vector charset golden` · REWRITE per D7: 53_decor_pend_cap removed with DECORATE; 52_charset rewritten for structural name rules; leave hash values (regen) + add the D7 note.
- **§7 vector coverage — L353** · `anti-rug, DECORATE gate/orphan, vote scoring + i128 accumulation past ±2⁶⁴ (28/37)` · DELETE that clause per D7.
- **§7 vector list — L339 & L377-389** · `**54 named, hand-authored adversarial constructions**` · REVIEW per D7: don't assert a stale count; add the renumber-pending note.
- **conf §6 frozen digests — L331-333** · three state_digest goldens · leave values (regen).
- **§5 generator op-weights — L304-305** · `op weights [POST,VOTE,COMMIT,…,TRADE] = [12,12,14,13,5,5,8,7,7,3,6,5,4]` · REWRITE: drop POST + VOTE → the 12 surviving ops + 12 weights. (Keep L301 activation_height=0 per D6.)
- **§4 n_decors detail — L272-280** · `**n_decors rec is the FULL on-wire record.**` · DELETE the whole paragraph.
- **§4 digest block — L239** · `u8 overflow_flag` · DELETE (D1).
- **§4 digest block — L238** · `u32 n_decors ; sorted by (txid[32],vout) STABLE` · DELETE the line.
- **§4 digest block — L236** · `u32 n_votes ; sorted by (target[32],vout), each: … i128 score[16]` · DELETE the line.
- **§4 digest preamble — L227** · `signed values are two's-complement LE; the i128 vote score is 16 bytes LE.` · REWRITE: drop the i128-vote-score clause.
- **§4 digest magic — L230** · `"SMv1"` · REWRITE → `"SMv2"` (D2).
- **§3 synthetic post id — L190-192** · `**Synthetic post id** (for votes/decorations…` · DELETE the whole bullet.
- **§2 128-bit helper — L123-124** · `…I128{hi,lo} helper (the signed vote accumulator + the §8 Σ's)` · REWRITE: remove `the signed vote accumulator + `; re-justify via the §8 Σ lease/price/legs.
- **§2 128-bit bullet — L118-119** · `**Vote accumulator** is signed 128-bit (Σ up − Σ down)` · DELETE the bullet.
- **§2 value representation — L138** · `koinu / price / vote-weight / lease numbers are exact 64-bit` · REWRITE: drop `vote-weight`.
- **§2 integer widths — L107** · `koinu / price / vote-weight are uint64.` · REWRITE → `koinu / price are uint64.`
- **cross-refs — L30 & §7 pointers** · `scenario combined 4c84238f…` · REVIEW: after regen, sweep the doc for old hashes.

## FILE 4: README.md

- **test layers — L102** · `all-cap forfeit, i128 accumulation past ±2⁶⁴, the fee oracle` · REWRITE: remove `i128 accumulation past ±2⁶⁴, `.
- **test layers — L100** · `2. **scenario** — 51 named, hand-authored edge cases` · REVIEW per D7: don't assert a stale count.
- **run it — L81** · `51 named adversarial conformance vectors + combined digest` · REVIEW per D7.
- **overview — L48-50** · `the i128 vote accumulator + property sums) use math/bits and` · REWRITE: drop `the i128 vote accumulator + `.

## FILE 5+ (HISTORICAL — do NOT edit; optionally add a "superseded" banner)

- `docs/notes/protocol-spec-v1.md` — frozen v1 snapshot (15-opcode table, genesis/gated, UTF-8 posts, DECORATE, votes). Leave as-is.
- `docs/notes/state-digest-ecmh-plan.md` — ECMH design note (votes/decors sub-accumulators). Leave as-is.
- `docs/notes/pre-launch-review-2026-07-03.md` — records the MAX_PEND pin + indexer vote command (downstream work-item B). Leave as-is.

## GLOBAL POST-EDIT STEP (impl phase, not a text edit)

REGENERATE + re-pin EVERY frozen golden from the edited C reference (never hand-edit hashes):
conf §6 state_digests, §7 scenario `combined`, §8 `property_digest`, §9 fuzz + bfuzz, §10 reorg,
§11 reorgfuzz + meta, §13.2 ecmh `combined` + `empty_state_ecmh`. Adopt `SMv2` across all 7 impls
together. attrib/attrib-curve goldens are §4-only — unaffected unless the generator draw shifts.

## Remaining flags (not blockers)

- §3.10 TRADE "length 1..20" vs §3.1 "1..32" — pre-existing discrepancy, D9: flag only, don't fold in.
- conf §7 / README vector counts diverge already (54 vs 51) — unify during the impl recount, not now.
