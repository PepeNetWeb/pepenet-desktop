# Installing PepeNet (desktop)

The GUI client: wallet, names, Discover, and the dns/tls stack **in-process**.
A stock browser padlock still needs a one-time **Enable web access**.

Headless POSIX daemons (`dnsd` + `pepenet-tls` as boot services):  
[pepenet-tls/INSTALL.md](https://github.com/PepeNetWeb/pepenet-tls/blob/linux/INSTALL.md).

These docs currently track the **`linux` branch**.

---

## One command

### Windows — headless padlock (Windows Service)

Same one-liner as pepenet-tls: installs **`pepenet-web.exe`** as service
`PepeNetWeb` (boot, no GUI), plants CA + NRPT + PAC.

PowerShell (admin UAC):

```powershell
irm https://raw.githubusercontent.com/PepeNetWeb/pepenet-tls/linux/install.ps1 | iex
```

Command Prompt:

```bat
powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/PepeNetWeb/pepenet-tls/linux/install.ps1 | iex"
```

`pepenet-web` is this repo’s WIN32 target (chain sync + resolver + DANE
proxy, no Sokol). A GitHub MSI must contain `pepenet-web.exe` (linux-branch
WiX). Until then, build it and pass the path:

```
cmake --build build-win --target pepenet-web
$env:PEPENET_WEB_EXE='C:\path\build-win\pepenet-web.exe'
irm … | iex
```

The **GUI** MSI from [Releases](https://github.com/PepeNetWeb/pepenet-desktop/releases)
is a separate install (wallet / Discover). Enable web access in the app if
you want the tray client instead of the service.

Undo:

```powershell
$env:PEPENET_UNINSTALL='1'; irm https://raw.githubusercontent.com/PepeNetWeb/pepenet-tls/linux/install.ps1 | iex
```

```bat
set PEPENET_UNINSTALL=1 && powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/PepeNetWeb/pepenet-tls/linux/install.ps1 | iex"
```

### macOS / Linux — padlock daemon, no GUI

If you only want `https://*.pepe` and not the wallet:

```sh
curl -fsSL https://raw.githubusercontent.com/PepeNetWeb/pepenet-tls/linux/get.sh | bash
```

That is **not** this app. It builds `dnsd` + `pepenet-tls` and installs boot
daemons. Details in the tls INSTALL.

### macOS / Linux — this app, from source

There is no GUI one-liner yet (no Linux tarball on GitHub Releases). Build:

**macOS**

```sh
git clone --recurse-submodules https://github.com/PepeNetWeb/pepenet-desktop.git
cd pepenet-desktop
git checkout linux    # until merged to main
git submodule update --init --recursive
cmake -B build && cmake --build build
./build/pepenet.app/Contents/MacOS/pepenet --demo
```

Package: `packaging/package.sh` → `dist/pepenet-<ver>.dmg`.

**Linux (Ubuntu 24.04, first verified target)**

```sh
sudo apt install build-essential cmake pkg-config \
  libssl-dev libsqlite3-dev \
  libx11-dev libxi-dev libxcursor-dev libgl1-mesa-dev \
  libdbus-1-dev libsecret-1-dev zenity
# optional: libnss3-tools  (user NSS db via certutil)
git clone --recurse-submodules https://github.com/PepeNetWeb/pepenet-desktop.git
cd pepenet-desktop
git checkout linux
git submodule update --init --recursive
cmake -B build && cmake --build build
./build/pepenet --demo
```

Tarball: `packaging/package-linux.sh` → `dist/pepenet-<ver>-linux-<arch>.tar.gz`
(`bin/pepenet` + `resources/` + `.desktop`). Sokol is X11 (Wayland via
XWayland). Close-to-hide uses StatusNotifierItem; wallet keys use libsecret.

**Windows from source** — MSYS2 UCRT64:

```sh
pacman -S mingw-w64-ucrt-x86_64-{gcc,cmake,ninja,openssl,sqlite3}
git submodule update --init --recursive
cmake -B build-win -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-win
./build-win/pepenet.exe --demo
```

MSI: `packaging\package-win.ps1 -WixDir C:\path\to\wix3 -ToolchainBin C:\msys64\ucrt64\bin`.

Args: `pepenet [--demo] [dbpath] [peer-ip] [coin]` — defaults `~/.pepenet/pep.db`
(`%USERPROFILE%\.pepenet\pep.db` on Windows), seed peer, `pep`.

---

## Enable web access

Discover → Visit, and a real browser padlock, need a consented system
install (DNS & Web → **Enable web access**). The resolver and DANE proxy
already run in-process. The helper only plants OS trust / DNS / proxy
routing. Uninstall reverses it. Quit leaves the wiring planted but inert
(dead ports = PepeNet is off).

Do **not** copy `pepenet-tls/install.sh` here: that script plants OS bits
and exits; it never starts this app.

| OS | Trust | DNS / browser path | `:443` | Elevation | Helper |
|---|---|---|---|---|---|
| macOS | login keychain (GUI auth = consent) | `/etc/resolver/pepe` + PAC (`networksetup`) | pf rdr → `:8445` (best-effort; PAC is primary) | one admin prompt (`osascript`) | `packaging/install-helper.sh` |
| Linux | optional `~/.pki/nssdb` + system CA (`update-ca-certificates`) | systemd-resolved `~pepe` on `lo` + GNOME/KDE PAC | nftables rdr → `:8445` (best-effort) | pkexec if present, else sudo | `packaging/install-helper-linux.sh` |
| Windows | current-user Root store (OS warning = consent) | NRPT `.<tld>` + HKCU PAC | app binds `:443` directly | UAC for NRPT only | `packaging/install-helper.ps1` |

PAC (`http://127.0.0.1:8444/proxy.pac`) is the **primary** browser route on
every OS: DoH skips OS DNS; mac pf loopback rdr is unreliable; Windows
VPN leak-blockers drop even loopback `:53`. A foreign PAC is never
clobbered.

Firefox: `security.enterprise_roots.enabled` is flipped in each profile’s
`user.js`. Fully quit and reopen Firefox.

Always-on for the **app** (engines stay warm, window hide-on-close):

- macOS: login item (SMAppService / LaunchAgent), Settings toggle
- Linux: XDG `~/.config/autostart/com.pepenet.app.desktop`
- Windows: HKCU Run (and the MSI one-liner’s scheduled task)

That is login-scoped, unlike `get.sh`’s boot daemons.

---

## Ports (loopback)

| Port | Role |
|---|---|
| 15353 | DNS resolver |
| 8443 | DANE proxy |
| 8444 | PAC + CONNECT front door |
| 8445 | mac pf / Linux nft redirect **target** — do not dial |
| 443 / 53 | Windows only: bound directly (no privileged ports) |

---

## Layout

CMake is `WIN32` / `APPLE` / `UNIX`. A Linux port is a third implementation
of `platform.h` (`platform_linux.c`, `sokol_impl_linux.c`, `tray_linux.c`,
`sysinstall_linux.c`), not a fork. Submodules (`dns/`, `tls/`, `indexer/`,
`mesh/`) compile unchanged; Windows uses `src/compat/win/` POSIX shims.

Data: `~/.pepenet/` (override in Settings). Linux config that must outlive a
relocated data dir: `~/.config/pepenet/config`.

---

## Packaging

| Script | Artifact |
|---|---|
| `packaging/package.sh` | ad-hoc or notarized `.dmg` (`CODESIGN_ID`, `NOTARIZE=1`) |
| `packaging/package-win.ps1` | per-user MSI |
| `packaging/package-linux.sh` | `pepenet-<ver>-linux-<arch>.tar.gz` |

macOS `.app`: OpenSSL 3 is static, no Homebrew dylibs. Linux tarball links
distro OpenSSL 3.
