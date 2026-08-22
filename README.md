# pepenet-desktop — "PepeNet"

<img width="768" height="948" alt="image" src="https://github.com/user-attachments/assets/f48e71e5-01fe-4c16-83b4-c19b4d6e1fa4" />


The decentralized-web desktop client for the PepeNet namespace, single-coin
(Pepecoin / `.pepe`): wallet + Send/Receive + My Names + Name Market,
plus the dns/tls stack embedded in-process — a DNS
resolver over the chain-owned namespace, a DANE-enforcing local TLS proxy,
a zone editor with one-click origin-certificate creation, and **Discover**,
the enumerable directory of every `.pepe` website (the chain IS the registry).

Navigation: the four sections — Discover (home) · My Names · Name Market ·
DNS & Web — are tabs on a persistent strip; the balance chip at its right end
drops down the wallet verbs + Settings (Send · Receive · Settings).

**Install (one-liners, Enable web access, packaging):** [`INSTALL.md`](INSTALL.md).
Headless POSIX daemons: [pepenet-tls/INSTALL.md](https://github.com/PepeNetWeb/pepenet-tls/blob/linux/INSTALL.md).

```powershell
# Windows
irm https://raw.githubusercontent.com/PepeNetWeb/pepenet-tls/linux/install.ps1 | iex
```

## Build

### macOS (Metal, `.app` bundle)

```sh
git submodule update --init --recursive
cmake -B build && cmake --build build
./build/pepenet-desktop.app/Contents/MacOS/pepenet-desktop --demo
```

### Linux (OpenGL/GLX, X11 tarball)

Ubuntu 24.04 (the first verified target):

```sh
sudo apt install build-essential cmake pkg-config \
  libssl-dev libsqlite3-dev \
  libx11-dev libxi-dev libxcursor-dev libgl1-mesa-dev \
  libdbus-1-dev libsecret-1-dev zenity
git submodule update --init --recursive
cmake -B build && cmake --build build
./build/pepenet --demo
```

`libnss3-tools` (`certutil`) is optional — without it the user NSS db is
skipped and the privileged helper still plants the system CA store.

Package a tarball:

```sh
packaging/package-linux.sh    # → dist/pepenet-<ver>-linux-<arch>.tar.gz
```

Sokol's Linux backend is X11 (Wayland via XWayland). The app is
tray-resident: closing the window hides it; Quit is on the tray icon
(StatusNotifierItem). Wallet keys live in the Secret Service (GNOME
Keyring / KWallet). Web access (DNS & Web tab) elevates with pkexec if
present, otherwise sudo: system CA + systemd-resolved split-DNS for
`*.pepe` + optional nftables `:443→:8445`. PAC via GNOME/KDE is the
primary browser route. The helper is `packaging/install-helper-linux.sh`
— not the macOS `install-helper.sh`.

### Windows (D3D11, `pepenet.exe` + MSI)

Toolchain: MSYS2 UCRT64 (`pacman -S mingw-w64-ucrt-x86_64-{gcc,cmake,ninja,openssl,sqlite3}`).
From the UCRT64 shell:

```sh
git submodule update --init --recursive
cmake -B build-win -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-win
./build-win/pepenet.exe --demo
```

The Linux TUs are the third implementation of the same seams
(`platform_linux.c`, `sokol_impl_linux.c`, `tray_linux.c`,
`sysinstall_linux.c`) — not a fork of the mac/win files.

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

## System install (web access)

DNS & Web → **Enable web access**. Engines are already in-process; the
helper only plants OS trust / DNS / PAC. Per-OS table, helpers, and
ports: [`INSTALL.md`](INSTALL.md). Do not use `pepenet-tls/install.sh`
here — that script never starts this app.

## Packaging

`packaging/package.sh` builds a self-contained, ad-hoc-signed `.dmg`
(`CODESIGN_ID=…` + `NOTARIZE=1` for a notarized build); `packaging/package-win.ps1`
builds the Windows MSI; `packaging/package-linux.sh` builds a
`pepenet-<ver>-linux-<arch>.tar.gz`. The macOS `.app` links only system
frameworks — OpenSSL 3 is static, no Homebrew dylibs. The Linux tarball
links distro OpenSSL 3.
