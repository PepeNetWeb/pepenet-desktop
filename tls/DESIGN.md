# pepenet-tls — a DANE-enforcing local TLS proxy for `.doge` / `.pepe`

**Status:** slices 1–4 built (`make test` 32/32). The resolver, proxy, name-constrained
CA, and DANE dial are each unit-proven; the `serve` binary + dnsd `--tls-redirect` hook +
`install.sh` are wired but the privileged end-to-end run (browser → `.doge` padlock) still
wants a live verification pass. This document is the architecture and, in particular, the
**security model** the implementation must honor. Sliced build plan at the end.

**One TLD per install.** A given box is a `.doge` network *or* a `.pepe` network, never
both — selected with `ca_set_tld` / `--tld doge|pepe` / `$PEPENET_TLD` (default `doge`).
The root is bounded to that single TLD, so a doge box's hot key cannot mint a `.pepe`
leaf at all. Roots live per-TLD at `~/.pepenet/pepenet-root-<tld>.{crt,key}`.

## 1. What this is and why

The pepenet namespace already publishes an **authenticated key directory**: a name's
owner is the only signer, and `pepenet-dns` (`dnsd`) serves that owner's records —
including **DANE** records (`TLSA`, `SSHFP`, `OPENPGPKEY`) — resolved off the chain +
mesh with no certificate authority anywhere in the trust path. The chain *is* the CA.

Browsers, however, do not speak DANE. So today `https://foo.doge` resolves fine but shows
a certificate warning: the origin's self-signed leaf chains to no CA the browser trusts.
This component closes that last gap. It is the payoff line of the whole DNS effort —
**CA-free authenticated TLS**: a padlock on `foo.doge` whose trust root is the Pepecoin /
Dogecoin chain, not Verisign.

It works by interposing a **local, name-constrained TLS proxy** between the browser and
the origin. The proxy authenticates the origin against the owner-published `TLSA` record
(this is real DANE-EE verification), and only then presents the browser a leaf it trusts —
minted on the fly by a local root CA that **can only ever vouch for this box's one TLD
(`.doge` *or* `.pepe`)**.

This is deliberately a local, opt-in trust decision by the machine's operator, bounded by
a name constraint. It is not a public CA and issues nothing for the real DNS namespace.

## 2. Threat model & the load-bearing security pillar

Installing *any* root into a browser/OS trust store is the most dangerous thing this
project does. A root CA that can sign `google.com` and is stored hot on disk to mint leaves
on demand would be a catastrophe if the key leaked. The design neutralizes this with **one
non-negotiable pillar**:

> **The root CA carries an X.509 Name Constraints extension permitting only this box's one
> TLD (`.doge` *or* `.pepe`).** Every conforming verifier (macOS `SecTrust`, NSS/Firefox,
> Chrome/BoringSSL all honor `NameConstraints` on `dNSName`) refuses any leaf this root
> signs for a name outside that TLD.

```
    NameConstraints (critical):        # as built — src/ca.c name_constraints(), per-TLD
      permittedSubtrees: dNSName = <tld>         # doge OR pepe — RFC 5280 label-suffix:
                                                 #   matches foo.<tld>, rejects foo.com /
                                                 #   not<tld> / the *other* TLD
      excludedSubtrees:  iPAddress = 0.0.0.0/0   # close the IP-SAN bypass: a leaked
                         iPAddress = ::/0        #   key can't mint an IP-address cert
```

Two encoding notes proven in slice 1 (`ca_test`, both TLD configs): the TLD name carries
**no leading dot** — RFC 5280 dNSName constraints are label-suffix matched, so `doge`
already permits `foo.doge` while rejecting `foo.com`, `notdoge`, `pepenet.doge.evil.com`
(a name that merely *contains* the TLD), and crucially `pepenet.pepe` (the other TLD). And
`permittedSubtrees` is itself the allowlist — anything not matching a permitted
subtree of its type is denied — so no empty-`dNSName` exclusion is needed (that
form is ambiguous/risky). The IP exclusion is the one real add: `permittedSubtrees`
for `dNSName` does *not* constrain `iPAddress` SANs, so without it a leaked key
could still mint a cert for an IP literal.

Consequences we rely on:

- The CA key **is** hot (it mints leaves per-connection), but a theft lets the attacker
  MITM exactly `*.<tld>` on machines that installed *this specific* root — nothing on the
  real internet, and not even the other pepenet TLD. The blast radius equals the single
  TLD this box serves.
- Leaf names go in the SAN `dNSName` (never rely on CN), because NC is enforced against SAN.
- The constraint is marked **critical** so a verifier that cannot process it must reject,
  never silently ignore.

Secondary boundaries:

- **The origin-authentication step is the actual gate.** The proxy MUST NOT present a
  browser-trusted leaf for `foo.doge` and then relay bytes to an origin it did not
  DANE-verify. Mismatch ⇒ fail closed (§6).
- **Loopback only.** The proxy listens on `127.0.0.1`; it is never a network service.
- **Uninstall is first-class.** `trust.c --uninstall` removes the root from every store it
  touched; the CA files live only under `~/.pepenet/`.

## 3. End-to-end flow

```
  ┌─────────┐  1. resolve foo.doge     ┌──────────────────────────┐
  │ browser │ ───────────────────────► │ dnsd (resolver)          │
  │         │ ◄── A = 127.0.0.1 ────────│  rewrites A→loopback IFF  │
  │         │     (name has TLSA)       │  name has _443._tcp TLSA │
  │         │                           └──────────────────────────┘
  │         │  2. TLS ClientHello (SNI=foo.doge)
  │         │ ───────────────────────► ┌──────────────────────────┐
  │         │                          │ pepenet-tls (proxy)       │
  │         │                          │  a. read SNI              │
  │         │                          │  b. fold store → real A + │
  │         │                          │     _443._tcp TLSA(3 1 1) │
  │         │       ┌─── c. dial real origin, TLS handshake ───────┼──► real
  │         │       │    d. OpenSSL DANE: SPKI==TLSA, NO PKIX chain │   foo.doge
  │         │       ▼                                              │   origin
  │         │  e. mint foo.doge leaf ← name-constrained root CA    │
  │         │◄──── present leaf → browser GREEN LOCK ──────────────│
  │         │  f. splice plaintext both directions                 │
  └─────────┘                          └──────────────────────────┘
```

The proxy is a **double-terminating** TLS bridge: it terminates the browser side (presents
a trusted leaf) and originates a fresh TLS session to the origin (which it DANE-verifies),
then pipes plaintext between them. It is a MITM — but one the operator installed
deliberately, bounded to this box's single TLD, and gated on chain-authenticated origin identity.

## 4. DANE specifics — and why OpenSSL, not LibreSSL

The owner publishes, at `_443._tcp.foo.doge`, a record of the DANE-EE form:

```
    TLSA 3 1 1 <sha256(SubjectPublicKeyInfo of the origin's leaf)>
      usage    3 = DANE-EE   (the association IS the server's leaf; no PKIX chain required)
      selector 1 = SPKI      (pin the public key, so the origin may rotate the cert body)
      match    1 = SHA-256
```

`3 1 1` is the canonical CA-free pin: 35 bytes, fits the ≤80 B on-chain escape hatch, and
survives cert re-issuance as long as the keypair is stable. `dnsd` already serves `TLSA` at
`_443._tcp` (proven live).

**OpenSSL 3 enforces this for us**, against audited code — the origin verification is *not*
hand-rolled:

```c
    SSL_CTX_dane_enable(ctx);
    SSL_dane_enable(ssl, "foo.doge");
    SSL_dane_tlsa_add(ssl, /*usage*/3, /*selector*/1, /*mtype*/1, spki_sha256, 32);
    /* disable PKIX chain building; DANE-EE 3 needs no CA */
    /* SSL_connect() now fails the handshake unless the origin leaf SPKI matches */
```

**Toolchain gotcha (verified on this box):** macOS's system `/usr/bin/openssl` is
**LibreSSL 3.3.6, which has NO `SSL_dane_*` API**. Homebrew `openssl@3` is present and
`_SSL_dane_tlsa_add` is confirmed in its `libssl` — so we build and link against
`/opt/homebrew/opt/openssl@3` explicitly (`-I.../include -L.../lib -lssl -lcrypto`), never
the system default. This must be pinned in the Makefile, not left to `PATH`.

## 5. Components

New sibling repo `pepenet-tls/` (keeps OpenSSL — the family's first heavy dependency — out
of the lean `dnsd` resolver; the proxy links it, the resolver does not).

| File | Responsibility |
|------|----------------|
| `src/ca.c` | Generate the **name-constrained** root (≈10 y) into `~/.pepenet/pepenet-root.{crt,key}`; mint + cache per-SNI leaves (short TTL, SAN `dNSName=<name>`) signed by it. |
| `src/trust.c` | Install / uninstall the root in the **user** store: macOS `security add-trusted-cert -r trustRoot` (login keychain, GUI auth = consent); Linux `certutil -A` into `~/.pki/nssdb` (unprivileged; `certutil` missing is a no-op). The Linux **system** store (`/usr/local/share/ca-certificates` + `update-ca-certificates`, or Fedora `update-ca-trust`) is `install-linux.sh` as root — there is no keychain GUI, so polkit/sudo is consent. |
| `src/proxy.c` | `127.0.0.1` TLS listener; SNI → fold zone (reuses `dns_fold`/`zone_apply`/`sp_view_*` from `pepenet-dns` + `pepenet-mesh`, **unchanged**) → OpenSSL-DANE dial to the real origin → present minted leaf → splice plaintext. |
| `src/main.c` | Daemon glue: open the shared carrier store read-only (WAL read-conn, exactly as `dnsd`'s resolver thread does), event loop. |
| `install.sh` | The one privileged step. Darwin: plant the CA (`install-ca`), write `/etc/resolver/<tld>`, add the pf redirect `127.0.0.1:443 → :8443`. Linux (`install-linux.sh`): nssdb as the user, system CA store, systemd-resolved split-DNS on dummy `pn-<tld>` (`~$TLD` → `127.0.0.1:15353`, never a global `DNS=`), nftables `:443 → :proxy` (best-effort). |

**Reuse, do not reimplement:** zone folding, ownership view, and record decode all come
from the existing `pepenet-dns` / `pepenet-mesh` trees by linking, matching how `dnsd`
itself was assembled.

### Two changes outside this repo

1. **`dnsd` resolver — the interception hook.** New `--tls-redirect <loopback-ip>` flag:
   when a queried name has a `_443._tcp TLSA`, answer its `A`/`AAAA` as the proxy's loopback
   address instead of the true IP. Non-web `A` records pass through unchanged. The proxy
   still learns the *true* origin IP by folding the store directly, so no resolver
   round-trip and no rewrite race.
2. **Privilege / port 443.** The proxy runs **unprivileged** on `127.0.0.1:8443`. The
   privileged `install.sh` adds a pf anchor redirecting loopback `:443 → :8443`, so the
   daemon never needs root at runtime. (The install step is already privileged — it writes
   `/etc/resolver` and touches the trust store — so co-locating the pf rule there is free.)

## 6. Fail-closed behavior

On **TLSA mismatch / no TLSA / origin unreachable**, the proxy must never proxy to the
unverified origin. It still completes the *browser-side* handshake with a minted `foo.doge`
leaf (the browser trusts it) but serves a **local error page** — "DANE verification failed
for foo.doge" — and closes. Presenting the trusted leaf here is safe because the content is
our own diagnostic, never origin bytes we could not authenticate. This gives a legible
failure instead of a raw connection reset.

## 7. Build slices

1. **CA + trust.** `ca.c` mints the name-constrained root + a leaf. Prove with `openssl
   verify` that the root validates a `foo.doge` leaf and **rejects** a `foo.com` leaf (the
   Name-Constraints test — the security pillar, tested first). `trust.c` install/uninstall
   round-trips the macOS login keychain. *No proxy yet.*
2. **DANE dial (the security core, in isolation).** Given a name, fold its `TLSA` from the
   store and dial the origin with OpenSSL DANE; assert accept on a matching self-signed test
   origin and reject on a mismatched one. This is the actual trust boundary; it is proven
   before any splicing exists.
3. **Proxy splice.** Wire SNI → fold → DANE-dial → mint → splice. A real `.doge` origin
   loads in a browser with a green lock, end to end.
4. **`dnsd` redirect hook + `install.sh`.** The loopback rewrite + pf/resolver install;
   full `dig`-then-browser demo on a clean machine.
5. **Fail-closed UX.** The §6 mismatch page; never relay unauthenticated origin bytes.

## 8. Trust tiers — from the trustless proxy to a phone-friendly quorum CA

**Status: design direction, not built.** §1–7 describe the *trustless* tier: a local,
name-constrained proxy that DANE-verifies every origin against the chain. That tier is the
integrity anchor of the system, but it has a footprint — every client installs a root **and**
runs a background proxy that folds the store / reaches the mesh. Fine on a laptop, impossible
on an unrooted phone. This section defines the tiers below it, and the one most users will
actually run.

### 8.1 The trust ↔ footprint spectrum

| Tier | Trust assumption | Client footprint | Phone? |
|------|------------------|------------------|--------|
| Full node + native DANE | trustless (chain is the CA) | chain sync + p2p + DANE-capable client | no |
| **Local proxy + personal root** (§1–7, today) | ~trustless: your own MITM, DANE-checked, name-constrained | root install + background proxy | no |
| Light client + M-of-N CA verify | M independent witnesses must agree | root install + small verifier (no chain sync) | no (needs a client) |
| **Threshold-quorum CA + root install** | M-of-N operators must collude to forge | **root + a DNS setting** | **yes** |
| Single CA + root install | trust one operator (Let's-Encrypt-like) | root + a DNS setting | yes |

Only the bottom two run on a stock phone (install a config profile carrying a root; set Private
DNS). The **threshold-quorum CA** is the sweet spot: the footprint of the single-CA tier, but the
forge-threshold of a quorum.

**Targeted tiers: exactly two.** The table is the analysis of the space, not the roadmap. The
system ships (a) the **trustless tier** — the local proxy of §1–7, the desktop product, built —
and (b) the **quorum-CA tier** — root + Private DNS, the phone/browser product for everyone else.
The intermediate shapes (light-client M-of-N verify, personal-watchdog phones, header/state-root
app clients) are deliberately **not** targeted: each adds a client stack to build, explain, and
secure for a marginal trust gain the watchdog architecture (§8.5) already polices. One trustless
solution, one slightly-less-trustless solution, nothing in between. Every tier validates the same
owner-published TLSA — tiers differ in **who checks**, never in **what is true**.

### 8.2 Why not just install several CA roots (the OR-trust trap)

Stock TLS validates a leaf against **any one** trusted root — one issuer signature, one chain. So
installing N roots gives **OR-trust**: any single one can forge any `.pepe` name. That is the
classic WebPKI weakest-link problem, and the *opposite* of a quorum. "Require multiple CAs to
agree" is the right goal, but stock browsers cannot express it — the AND must be enforced
somewhere the browser already respects.

### 8.3 Threshold signatures — a quorum a stock browser accepts

> **The N CAs jointly control a single root key via threshold cryptography (distributed key
> generation at setup; no operator ever holds the whole key). Producing one signature requires
> M-of-N operators to cooperate. The browser trusts one root and verifies one signature — which
> can only exist if M CAs agreed.**

This is the only construction that yields real quorum with *zero* client logic beyond a normal
root install, so it is the only quorum that works in Safari on an iPhone. The quorum lives
entirely in the signing ceremony; to the browser it is an ordinary CA.

Use **M-of-N, not N-of-N** (e.g. 2-of-3): N-of-N maximizes security but any single operator
offline or refusing halts all issuance; M-of-N tolerates a down/bad operator while still
requiring M to collude to forge.

The §2 pillar carries over unchanged: the quorum root is **name-constrained to the one TLD**, so
even a total quorum compromise cannot mint outside `.pepe`, and cannot touch the real internet.

**WebPKI bleed-through — the honest caveat, stated once.** Installing the quorum root does not
*remove* the ~150 built-in roots, and browser chain validation performs no "is this TLD
ICANN-delegated?" check — so on a stock phone a cert for `foo.pepe` chaining to **any** trusted
anchor validates. The phone tier's real trust statement is therefore **OR(quorum, every WebPKI
CA)**: a *compromised* public CA plus a network-position attacker can MITM `.pepe` exactly as they
could MITM `.com`. (A *compliant* CA cannot — the CA/B Baseline Requirements have banned issuance
for non-ICANN names since 2015; issuing for `.pepe` is an auditable violation.) Three offsets:
the **trustless tier is immune by construction** (the browser only ever sees the local proxy's
leaf; the origin is DANE-checked, and a WebPKI-signed origin cert has the wrong SPKI → fail
closed); **any WebPKI `.pepe` cert is *ipso facto* mis-issuance** — unlike a mis-issued `.com`
cert, it is distinguishable from legitimate issuance at a glance, and since Chrome/Safari require
SCTs the attacker must largely log it to use it, self-incriminating (→ the CT-monitoring watchdog
duty, §8.5); and the attack still requires winning the network path against honest resolution.
The clean fix is browser-side and costs nothing (§8.8).

### 8.4 On-chain-gated issuance — passive watch-and-sign

**The owner never asks the CA for a cert; the chain publication *is* the request.** The owner
already, for DANE, (1) holds their own keypair and (2) publishes `_443._tcp.foo.pepe TLSA 3 1 1 =
sha256(SPKI)` on chain/mesh — an owner-signed act. The quorum CA simply **watches** for that record
and ratifies it. The private key never touches the CA; the owner *creates* the cert (their key), the
CA only *signs off* on it.

```
  1. owner publishes TLSA   _443._tcp.foo.pepe TLSA 3 1 1 <sha256(SPKI)> — owner-signed, on chain/mesh
  2. CA observes + fetches  sees the record; connects to the live origin, reads its leaf's SPKI
  3. CA checks the leash    require sha256(SPKI) == the on-chain TLSA — bind ONLY the pinned key
  4. M-of-N threshold sign  operators co-produce ONE sig under the joint, name-constrained root → durable cert
  5. short-lived + logged   days not years (no OCSP/CRL reliance); published to the transparency log (§8.5)
```

So each CA is a **pure transcriber of chain state into X.509**, with essentially zero discretion:
its only job is "bind exactly the key the on-chain TLSA already commits to." M CAs agreeing is then
not arbitrary trust — it is **M independent witnesses attesting to the same on-chain fact**, and a
cert whose SPKI ≠ the on-chain TLSA is *provably wrong* to any watchdog (§8.5). The owner's on-chain
record is the leash on the CA. Step 2's "fetch the live key" is literally the local proxy's DANE step
(§3) — the quorum CA *is* that minting step moved server-side and made durable.

Because the issued cert's SPKI still matches the TLSA, **one cert serves both worlds**: DANE-aware
clients accept it (SPKI == TLSA) and browsers accept it (chains to the quorum root). Rotation stays
trivial — new key ⇒ update the TLSA ⇒ CA reissues; the chain is the single source of truth for which
key is `foo.pepe`.

**Active alternative.** An owner who wants to drive issuance on demand (or rotate without waiting on a
publication) can instead run an ACME-style client: submit a CSR + prove control of the on-chain owner
key (sign a nonce each CA checks against `names`/`epochs`). Same leash — the CA still binds only a key
the chain authorizes — just owner-initiated rather than observed.

**The tie, in one line: the leaf and the TLSA are two attestations of the same key.** The TLSA is
the owner saying "hash(K) is my site's key" (mesh-signed, admitted only because the signer is the
fold's current owner); the leaf is the quorum saying "K is this name's key, until Thursday"
(threshold-signed under the constrained root). Same SubjectPublicKeyInfo in both — no reference,
no extension, identity of the key. The cert is the TLSA transcoded into X.509 and given an expiry;
the chain/mesh stays the sole root of authority, which is exactly what keeps a lying quorum
*provably* wrong rather than merely suspicious. No proof-of-possession ceremony is needed: the
binding was authorized by the owner's mesh signature, a cert for a key you don't hold is useless
(you cannot complete the handshake), and the watch step reads the live origin's key anyway.

**Issued-leaf distribution (pinned).** The quorum publishes each issued leaf back into the mesh as
a record in the name's zone, beside the TLSA it ratifies — the mesh is the one distribution channel
for both halves of the binding. A leaf is public, self-verifying data (it chains to the quorum root
and names its key), so **anyone** may re-serve it: pickup mirrors need no vetting, and a malicious
mirror can at worst withhold (liveness), never forge.

### 8.5 The trustless tier becomes the watchdog

Keep the full-node/DANE tier alive not for mass users but as the **enforcement backstop**. Anyone
running it verifies certs against **on-chain ground truth**, so if the quorum ever signs a key that
does not match the chain, it is not merely *detectable* (WebPKI Certificate Transparency stops here
— it has no notion of "should this cert exist") but **provably wrong**. Convenience tier for people;
trustless tier as the auditor that keeps it honest. The system keeps a decentralized conscience even
as most users run the easy path.

**Watchdog duty #2 — monitor the WebPKI's CT logs for `.pepe`.** Since no public CA may issue for
a non-ICANN name (§8.3), *any* `.pepe` entry in a CT log is unambiguous mis-issuance — a bright-line
alarm and a CA-killing incident report, cheaper and stronger than the detection real domains get
(a mis-issued `.com` cert looks legitimate in CT; a `.pepe` one convicts itself). One standing
query over the public logs; automatable day one.

### 8.6 Deployment — mesh on the back, ACME on the front

**The hosting box never touches the mesh.** Publishing the zone (the A record, the TLSA) is a
*wallet act* — it needs the owner key, so it happens from the desktop app (the DNS & Web tab),
never from the server. Same shape as ordinary DNS: your VPS never talks to your registrar. The
host needs exactly two things, neither of which is a mesh connection:

1. **the origin key + cert as files** — in the trustless tier this is the whole story: the
   self-signed origin cert (`sscert`, ~10 y) is copied in once and never renewed, because DANE
   clients check the pin, not the expiry;
2. **a fresh quorum leaf periodically** — the quorum tier's only recurring task, because
   browser-facing leaves are short-lived (revocation-by-expiry, §8.4).

Leaf refresh reuses the web's existing muscle instead of inventing one:

- **ACME facade.** The quorum (or any mirror) exposes a standard ACME directory over plain HTTPS,
  so certbot / acme.sh / Caddy / Traefik work unchanged. The authorization step is *degenerate*:
  there is no HTTP-01 or DNS-01 challenge, because the owner's standing TLSA **is** the
  authorization — the facade only checks the CSR's key matches the pin and hands over the leaf
  that already exists. Less ceremony than the real web asks of a host today.
- **Pickup endpoints.** `curl https://<mirror>/cert/<name>.pepe` in a cron job, or fetch the leaf
  through DNS itself (it rides the mesh as a zone record any public mirror serves, §8.4). For
  hosts that allow cron but not new software.
- **Owner-push.** For panel-style hosting with no shell: the desktop app sees the renewed leaf
  arrive in the mesh and offers the bundle for upload — the workflow every hosting panel already
  has for custom certs.

None of these intermediaries is trusted: the private key never moves, and the leaf is
self-verifying, so facades and mirrors are pickup windows, not authorities.

### 8.7 Fronting — the mass-hosting tier

Most operators will not run a TLS terminator at all; they will point their name at a
`.pepe`-aware fronting service (the Cloudflare shape): the fronter mints an origin key for the
site, the owner publishes the A → fronter's IP and the TLSA → fronter's key, and the actual
origin is any dumb host behind it. The quorum machinery above is unchanged — the fronter's key is
just the pinned key.

**Why fronting is acceptable here when it centralized the real web: the name never becomes
hostage.** Ownership, the A record, and the TLSA remain wallet-signed acts on the chain/mesh —
the control plane never belongs to the host. Leaving a fronter is one publish from the DNS tab
(re-point the A, pin a new key), and the fronter holds nothing that outlives the switch: an
origin key, not the name.

Stated honestly: a fronter terminates TLS, so it sees plaintext for the sites it fronts — the
inherent price of the tier, not of this design. And a fronter is the natural entity to also run a
quorum seat and the ACME facade — permitted, **bounded by the one-seat rule (§8.9)**.

### 8.8 Adoption — the blockers are not cryptographic

- **To a browser it is already just a CA.** One root, one signature — it works *today* with a manual
  root install + Private DNS. No standards process gates the manual-install path.
- **Zero-install (default trust store) is walled off by namespace legitimacy, not crypto.** Root-program
  admission (Mozilla/Apple/Chrome, CA/Browser Forum Baseline Requirements, WebTrust audits) is bound to
  ICANN TLDs; `.pepe` is not delegated, so a `.pepe`-constrained root is categorically inadmissible to
  the *built-in* store no matter how clean the ceremony.
- **The first browser ask is defensive, free, and never says "pepe": enforce the built-in store's
  own declared scope in code.** The BRs already say public CAs issue only under ICANN TLDs; browsers
  just don't check it at validation time. A rule — *chains to the built-in store never validate
  names outside ICANN TLDs* — has **zero legitimate breakage** (any cert it blocks is by definition
  a BR violation), closes the WebPKI bleed-through (§8.3) for every alt-namespace and internal name
  at once, and the namespace-scoped machinery already ships in every browser (the Public Suffix
  List, the `.onion`/`.local` special cases). A mitigation with no compatibility cost, defensible
  entirely on the WebPKI's own terms.
- **The constructive mechanism to steer toward** is not "trust our CA by default" but "let an
  OS/browser bind an *alt-namespace* to a name-constrained trust anchor + resolver, isolated from
  the WebPKI." The primitives already exist (enterprise/name-constrained roots, Private DNS,
  per-domain trust); the quorum CA is a well-behaved citizen of such a mechanism. Note the pair:
  the defensive ask scopes the *built-in* store away from us; the constructive ask scopes the
  *user-installed* anchor onto us. Both are general mechanisms that stand on their own merits.
- **Threshold issuance is a WebPKI-wide improvement, not a fringe favor.** The whole WebPKI has the
  any-one-of-~150-CAs-can-forge problem; a multi-party issuance root addresses it for the real web too.
  That is the standards narrative: demonstrate a fix for a known WebPKI flaw that also happens to serve
  `.pepe`.

### 8.9 The real blocker: operator independence & governance

A quorum is only as strong as the independence of its members. **Run all N CAs yourself and the quorum
is theater — a single CA with extra steps.** The security materializes only when the N are genuinely
independent (different orgs, jurisdictions, infrastructure). So the threshold CA's value is unlocked by
a *governance* milestone, not a coding one:

- recruit independent operators; publish who they are and the independence rationale;
- govern membership changes — and note that **rotating the member set = rotating the threshold root**, a
  re-install for every client unless an intermediate + rotation story is designed up front (e.g. the
  joint root signs a rotatable intermediate; membership changes re-key the intermediate, not the
  installed root);
- fix M/N and separate the ceremonies: quorum-to-sign-a-leaf vs. quorum-to-change-membership;
- **the one-seat rule: a fronting operator (with its affiliates) holds at most ONE seat — always
  fewer than M.** A fronter (§8.7) already concentrates origin keys and traffic; if
  commercially-related entities held M seats, the party holding everyone's origin keys could also
  ratify keys nobody published. One seat keeps forging a collusion *beyond* the host — the
  watchdog (§8.5) would still convict such a cert after the fact, but the threshold is what makes
  it hard *before* the fact.

### 8.10 Roadmap

1. **Now** — manual root install + Private DNS; single-operator issuance to prove the flow end-to-end
   (honestly labeled single-trust until step 3).
2. **Deployment surface** — the ACME facade + pickup mirrors (§8.6) over the single operator;
   leaf-as-mesh-record distribution (§8.4); first fronting service (§8.7).
3. **Independence** — recruit independent quorum operators under the one-seat rule (§8.9); stand up
   the DKG + M-of-N ceremony; wire the on-chain issuance challenge and the transparency log; the
   trustless tier begins auditing.
4. **Mechanism** — lobby the alt-namespace name-constrained-trust-anchor mechanism, with threshold
   issuance as the WebPKI-wide selling point.

The cryptography is the easy part; **independence and namespace legitimacy are the milestones.**

## 9. Deferred / open

- **Firefox & Chrome trust on macOS** still want `certutil` (NSS) for browsers that ignore
  the login keychain; we flip `security.enterprise_roots.enabled` instead. Linux plants the
  system CA store (p11-kit) and uses the same pref; `certutil` into `~/.pki/nssdb` is the
  unprivileged bonus path.
- **`HTTPS`/`SVCB` RR (type 65)** for non-443 ports / ALPN hints — v1 assumes origin `:443`
  and `TLSA` at `_443._tcp`.
- **ECH / encrypted SNI** would hide the SNI the proxy routes on — out of scope; `.doge`
  origins are ours and won't deploy it in v1.
- **Desktop embed.** Long-term the proxy rides in `pepenet-desktop` like the resolver/mesh;
  OpenSSL-vs-embeddable-TLS for that build is revisited then (v1 is the standalone daemon).
- **DANE-TA (usage 2).** v1 pins DANE-EE (`3 1 1`) only — the CA-free case. TA support is a
  later add if a `.doge` operator wants an intermediate. `origin_from_zone` now
  **refuses** any other usage/selector/mtype (32-byte SHA-256 required).
- **Origin address policy.** Loopback / RFC1918 / link-local / multicast A
  records are not dialed (a `127.0.0.1` origin plus the lo0 `:443` rdr
  recursed into the proxy). Origin TCP connect is capped at 5s.
- **Trust-store plant.** `trust_install` refuses a PEM that is not the
  in-process name-constrained root, then installs a temp copy.
- Desktop threat model (P2P + proxy): `pepenet-desktop/docs/SECURITY.md`.
