# Security model — P2P overlay and the local HTTPS proxy

This is the threat model and the controls for pepenet-desktop: the chain-wire
overlay (`dn*` / zone gossip) and the DANE-enforcing loopback TLS proxy.
It is the document the 0.2.3 audit produced; code cites below are the
load-bearing sites, not an exhaustive map.

**Names cannot be stolen on the wire.** Topology, CPU, and local-origin
dialing can still be abused. Those are the remaining classes.

---

## 1. Two planes

| Plane | Trust root | What a peer can do |
|-------|------------|--------------------|
| **Zone state** | Chain ownership (lease) + owner ECDSA (or a scoped §2.2 cert) | Relay signed ops. Cannot install records for a name they do not own. |
| **Topology / bandwidth** | Self-asserted `/pepenet-` user-agent + TCP | Point our overlay dials, consume slots, ask for zone dumps. |

The proxy sits beside both: it reads the same owner-signed zone, DANE-verifies
the origin, then presents the browser a leaf from a **name-constrained local
CA** (`.pepe` only).

---

## 2. Zone gossip (what is actually authenticated)

Admission is `sp_state_admit` (`mesh/src/state.c`):

1. Parse + §3.1 name rules.
2. `owner_now` — no lease, no admit (cheap reject).
3. **Owner-key check before ECDSA** — a hostile dump signed by the peer’s own
   key used to burn a secp verify per op. Non-owner is now a hash160 compare.
4. ECDSA (low-S) over `op_id`.
5. Optional delegation cert (scope bit + owner-minted).
6. Anchor on our header chain (or hold if we are behind).
7. LWW / floor / per-name budget inside `BEGIN IMMEDIATE`.

One name per `dnzdat`. No-change dumps are silent (anti-entropy every 60s).
Hold queue stores ahead-of-tip ops, **one slot per blob**.

**Still unauthenticated:** who may *relay* a valid op. That is intended —
flood of *valid* owner ops still costs ECDSA (dup is after crypto). Cap
inbound `dnzget` (2s/peer) limits the cheap dump amp.

---

## 3. Overlay membership (the remaining structural gap)

`/pepenet-` in `version.user_agent` is **not a credential**. Anyone can send
it. Controls that bound the blast radius:

| Control | Why |
|---------|-----|
| Handshake before any other command | Bare TCP used to `getdata` the whole serve window. |
| `dngetaddr` / `dnaddr` only from a marked, `up` peer | Unmarked chain peers used to poison `dnet=1` and we re-gossiped it. |
| `dnet=1` vouches sit out 1h after a failed dial | NAT/dead lists no longer stall the serve thread every 10 minutes. |
| One mesh gossip slot per IP | Extra inbound used to `send_inv_all` again. |
| **≤16 inbound mesh handles** | Botnet of marked inbound cannot fill `SERVE_MAX_CONN`. Outbound mesh seats stay available. |
| Mesh dials one `/16` | Same eclipse rule as chain `chain_topup`. |
| Ignore a second `version` on a live conn | Cannot flip agent to `/pepenet-` and steal a slot. |
| P2P payload checksum (sha256d) | Magic was checked; checksum is now checked on recv and the serve parse. |
| `self` only from **outbound** `addr_recv`, globally-routable IPv4 | First inbound peer used to make us advertise their IP. |

**Not done (needs a protocol bump):** a node identity key in version, or
“only mesh-dial addresses whose mark *we* observed.” Until then, treat the
mark as a hint plus the caps above — not as authentication.

---

## 4. Local HTTPS / DANE proxy

End-to-end (DESIGN.md §3 still holds):

1. Browser PAC / pf rdr → `127.0.0.1` only.
2. CONNECT is TLD-checked and **never dials the CONNECT host** — splice to
   `:8443`. Non-`.pepe` → 403.
3. SNI must be a concrete name under this box’s TLD (`ca_leaf_mint`); no `*`.
4. Resolve: ownership oracle, then A + **TLSA 3 1 1 only** (32-byte SHA-256).
5. Origin A must be globally routable (no loopback / RFC1918 / link-local /
   multicast). `A=127.0.0.1` plus the lo0 `:443` rdr used to recurse into
   this process.
6. Origin TCP connect is 5s bounded; `SSL_connect` inherits `SO_RCVTIMEO`.
7. Splice plaintext **only** on `DANE_OK`. Mismatch / down / no zone → local
   error page (every field HTML-escaped).
8. Root CA: critical Name Constraints (TLD DNS + exclude all IPv4/IPv6),
   `CA:TRUE,pathlen:0`, key file 0600, data dir 0700.
9. `trust_install` refuses a PEM that is not this process’s in-memory root,
   then plants a temp copy — a swapped unconstrained CA in `~/.pepenet` is
   not what gets `security add-trusted-cert`.
10. Quiet PAC/DANE tunnels drop after 120s idle. `--listen` is loopback-only.
    Linux `install-helper` refuses a `--cert` that is not `CA:TRUE` with
    NameConstraints for this TLD.

PAC / DANE connection caps: `PAC_CONN_MAX=8`, desktop `PROXY_CONN_MAX=8`
(login-item jetsam is 32 threads). Quit: splice polls 500ms and honors stop
so `webproxy_stop` can join.

---

## 5. Operator-trusted local CA (the dangerous step)

Installing *any* root is the most dangerous thing this app does. The pillar:

> The root may sign **only** this box’s one TLD. Conforming verifiers
> (SecTrust, NSS, BoringSSL) honor critical Name Constraints.

A stolen hot key MITMs `*.pepe` on machines that installed **this** root —
not `google.com`, not `.doge`. Same-uid malware that can read
`~/.pepenet/pepenet-root-pepe.key` is still in the `.pepe` blast radius;
keep the data dir 0700. Moving the key into the login keychain / Secure
Enclave is the next hardening step, not yet built.

The privileged helper (`install-helper.sh`) still copies a cert path into
the **system** store on Linux. That path should stay the same sealed root;
do not point `--cert` at an arbitrary file.

---

## 6. What we will not do

- Open the proxy on `0.0.0.0` in the desktop build.
- Splice origin bytes without a DANE-EE match.
- Admit zone ops for an unowned or foreign-signed name.
- Treat `/pepenet-` as a cryptographic identity (until a version-key exists).

---

## 7. Checklist (0.2.3)

| Item | Status |
|------|--------|
| Owner-signed zone admission | done |
| ECDSA after owner-key check | done |
| Handshake before getdata/dnaddr | done |
| dnaddr only from marked peers | done |
| Hold-queue dedupe | done |
| zget 2s/peer | done |
| Inbound mesh cap 16 + /16 mesh dials | done |
| Ignore extra version | done |
| P2P checksum | done |
| Self-IP from outbound + public IPv4 only | done |
| DANE-EE 3 1 1 only | done |
| No loopback/RFC1918 origin dial | done |
| Origin connect 5s | done |
| Mint only `*.<tld>` | done |
| Trust-store = in-memory root | done |
| Data dir 0700 / key 0600 | done |
| Splice idle timeout (120s) | done |
| PAC `/proxy.pac` exact path + `no-store` | done |
| `--listen` loopback-only | done |
| Linux helper `--cert` must be CA:TRUE + NC for TLD | done |
| Dup `op_id` skips ECDSA | done |
| Node identity key in version | **open** (needs a protocol bump) |
| Keychain-backed CA key | **open** (Secure Enclave / SecItem) |
