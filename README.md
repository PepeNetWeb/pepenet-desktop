# pepenet-desktop — "PepeNet"

The decentralized-web desktop client for the PepeNet namespace, single-coin
(Pepecoin / `.pep`): wallet + Send/Receive + My Names + Name Market from
pepenet-desktop's UI, plus the dns/tls stack embedded in-process — a DNS
resolver over the chain-owned namespace, a DANE-enforcing local TLS proxy,
a zone editor with one-click origin-certificate creation, and **Discover**,
the enumerable directory of every `.pep` website (the chain IS the registry).

Navigation: the four sections — Discover (home) · My Names · Name Market ·
DNS & Web — are tabs on a persistent strip; the balance chip at its right end
drops down the wallet verbs + Settings (Send · Receive · Settings).

No social plane — this app is the money + names + web client: wallet,
namespace, marketplace, and the decentralized-web stack (DNS + TLS + mesh).

## Build

### macOS (Metal, `.app` bundle)

```sh
git submodule update --init --recursive
cmake -B build && cmake --build build
./build/pepenet-desktop.app/Contents/MacOS/pepenet-desktop --demo
```

### Windows (D3D11, `pepenet.exe` + MSI)

Toolchain: MSYS2 UCRT64 (`pacman -S mingw-w64-ucrt-x86_64-{gcc,cmake,ninja,openssl,sqlite3}`).
From the UCRT64 shell:

```sh
git submodule update --init --recursive
cmake -B build-win -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-win
./build-win/pepenet.exe --demo
```

The submodule sources (`dns/`, `tls/`, `indexer/`, `mesh/`) compile
**unchanged** — `src/compat/win/` supplies the POSIX net/fs headers over
Winsock (a thin `sys/socket.h`, `poll.h`, `netdb.h`, … each routing into
`win_compat.c`: int-fd sockets, `flock`→`LockFileEx`, `getentropy`→
`BCryptGenRandom`, `SO_RCVTIMEO` timeval→ms). The macOS-specific TUs have
Win32 twins built by the `WIN32` branch of `CMakeLists.txt`:
`platform_win.c` (paths → `%USERPROFILE%\.pepenet`, config → HKCU, secrets →
Credential Manager), `tray_win.c` (`Shell_NotifyIcon` + WM_CLOSE-veto-hides),
`sokol_impl_win.c` (D3D11 + DWM dark titlebar), `trust_win.c` (CA into the
user Root store), `sysinstall_win.c` (NRPT `.pepe` route via
`packaging/install-helper.ps1` behind one UAC prompt). No pf on Windows and
no privileged ports, so the resolver also binds `:53` (the NRPT path) and the
proxy also binds `:443` (the browser path) directly — see `dnsnet.c` /
`webproxy.c`.

Package the MSI (per-user, no admin to install):

```powershell
packaging\package-win.ps1 -WixDir C:\path\to\wix3 -ToolchainBin C:\msys64\ucrt64\bin
```

Args: `pepenet-desktop [--demo] [dbpath] [peer-ip] [coin]` — defaults
`~/.pepenet/pep.db` (`%USERPROFILE%\.pepenet\pep.db` on Windows), the pep seed
peer, `pep`.

Dev hooks: `PEPENET_OPEN=<view|dialog>[,tok…]` (views: discover · names ·
market · receive · send · dns · settings; demo adds dialog/fixture states),
`PEPENET_SELFTEST=1` (shibwallet vectors in-process), `PEPENET_DRYRUN=1`
(ops build+sign+self-check, no broadcast).

## Architecture

Embedded engines on their own threads over shared state in `~/.pepenet/`,
UI reads projections/snapshots only (rules inherited from
pepenet-desktop/src/README.md):

- **chain sync** — `src/engine.c`: `indexer_main("sync")` → `pep.db`.
  The indexer pin is POST-consensus-simplification: names-only SM, DNS-label
  name charset `[a-z0-9-]` 1–32, no posts/votes/decorations.
- **ops worker** — `src/ops.c`: queued tx pipeline (send/claim/renew/sell/…),
  signs with the dev wallet through the signer seam. The one wallet key is
  also the name-owner key — and therefore the zone-signing key.
- **dns mesh + resolver** (slice 4) — `src/dnsnet.c` + `dns/` submodule:
  firehose mirror of the `0xD8` zone overlay (1 yr / 50 KB per name),
  UDP+TCP resolver on `127.0.0.1:15353`.
- **DANE TLS proxy** (slice 6) — `src/webproxy.c` + `tls/` submodule:
  name-constrained root, per-SNI leaf mint, loopback `:8443`.
- **directory** (slice 8) — `src/dirscan.c`: indexer `names` × dns-store fold
  join, double-buffered snapshot for the Discover view.

## Milestones — all DONE

1. Repo skeleton: submodules, CMake, social-stripped GUI, running against `pep.db`.
2. Per-overlay TTL in pepenet-social (dns store = 525600 blk / 50 KB) + pepenet-dns adoption.
3. `dnsd_core` extraction in pepenet-dns (embed seam; standalone dnsd unchanged).
4. Embedded dns engine: mesh thread + resolver thread on `:15353` + `dns-pep.conf`.
5. pepenet-tls patches: `pep` TLD, `proxy_serve_ctl` (stop flag + mint/verdict events).
6. Embedded DANE proxy on `:8443` + status/mint-log surface.
7. DNS & Web tab: install/uninstall (CA · `/etc/resolver/pep` · pf), status, zone editor.
8. Discover directory: `dirscan` join (names × dns fold) + badges + Visit (system browser).
9. Tray lifecycle: close = hide (engines warm), Quit = off; menu-bar status item.
10. Packaging (self-contained .app, static OpenSSL) + end-to-end padlock proof.

## Going live (the system install)

The Discover tab's **Visit** and a real browser padlock need a one-time,
consented system install (DNS & Web tab → *Install web access*): the `.pep`
root trusted in the login keychain (unprivileged), plus `/etc/resolver/pep`
and a pf `:443→:8443` redirect (one admin prompt, via
`packaging/install-helper.sh`). Uninstall reverses all three. Quit leaves them
planted but inert — a dead `:8443` is the legible "PepeNet is off" state.

Package a distributable: `packaging/package.sh` (ad-hoc signed .dmg;
`CODESIGN_ID=…` for a notarizable build). The `.app` links only system
frameworks — OpenSSL 3 is static, no Homebrew dylibs.

## Known limitations (v1)

- Shared `~/.pepenet/pep.db` with pepenet-desktop: don't run both at once (two sync writers).
- The wallet key is also the zone-signing key; cert-delegated hot zone keys are a post-v1 hardening.
- macOS pf loopback rdr is flaky; the DNS tab surfaces "pf not loaded" when it fails.
- Cold start scans the whole chain once before Discover populates (meld §7; no snapshots pre-quorum).
