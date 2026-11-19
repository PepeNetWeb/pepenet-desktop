#!/bin/bash
#
# pepenet-tls installer — one command, macOS and Linux.
#
#   curl -fsSL https://raw.githubusercontent.com/PepeNetWeb/pepenet-tls/main/get.sh | bash
#   curl -fsSL .../get.sh | bash -s -- --tld pepe
#   curl -fsSL .../get.sh | bash -s -- uninstall
#
# Clones the family, builds dnsd + pepenet-tls, installs them as boot
# daemons (systemd system units / LaunchDaemons — survive reboot and
# logout), then elevates to plant the CA / split-DNS / :443 redirect.
# install.sh by itself only does the OS half.
#
# Env: PEPENET_HOME (default ~/.pepenet), PEPENET_REF (default main),
#      PEPENET_TLD (default pepe), PEPENET_PEER (comma-separated host:port;
#      pep default pepenet.shibpost.com:33874,net.pepecoin.services:33874)
#
# Windows: install.ps1 (irm … | iex) — pepenet-tls is POSIX; the padlock
# there is pepenet-desktop.

set -euo pipefail

ORG="${PEPENET_ORG:-PepeNetWeb}"
REF="${PEPENET_REF:-main}"
HOME_DIR="${PEPENET_HOME:-$HOME/.pepenet}"
TLD="${PEPENET_TLD:-pepe}"
PEER="${PEPENET_PEER:-}"
COIN="pep"
DNS_PORT=15353
PROXY_PORT=8443
SRC="$HOME_DIR/src"
BIN_DIR="$HOME_DIR/bin"
GH="https://github.com/$ORG"

ACTION="setup"
while [ $# -gt 0 ]; do
    case "$1" in
        uninstall|--uninstall) ACTION="uninstall"; shift ;;
        --tld)  TLD="$2"; shift 2 ;;
        --peer) PEER="$2"; shift 2 ;;
        --ref)  REF="$2"; shift 2 ;;
        --home) HOME_DIR="$2"; SRC="$HOME_DIR/src"; BIN_DIR="$HOME_DIR/bin"; shift 2 ;;
        -h|--help)
            echo "usage: get.sh [uninstall] [--tld pepe|doge] [--peer host:port]"
            exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
case "$TLD" in
    pepe) COIN=pep;  PEER="${PEER:-pepenet.shibpost.com:33874,net.pepecoin.services:33874}" ;;
    doge) COIN=doge; PEER="${PEER:-pepenet.shibpost.com:22556}" ;;
    *) echo "TLD must be pepe or doge" >&2; exit 2 ;;
esac

os="$(uname -s)"
case "$os" in
    Darwin) os=macos ;;
    Linux)  os=linux ;;
    MINGW*|MSYS*|CYGWIN*)
        echo "pepenet-tls is POSIX. On Windows:" >&2
        echo "  PowerShell:  irm https://raw.githubusercontent.com/$ORG/pepenet-tls/$REF/install.ps1 | iex" >&2
        echo "  cmd.exe:     powershell -NoProfile -ExecutionPolicy Bypass -Command \"irm https://raw.githubusercontent.com/$ORG/pepenet-tls/$REF/install.ps1 | iex\"" >&2
        exit 1 ;;
    *) echo "unsupported OS: $os" >&2; exit 1 ;;
esac

log() { printf '==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

elevate() {
    if [ "$(id -u)" = 0 ]; then
        "$@"
    elif have sudo; then
        sudo "$@"
    elif have pkexec; then
        pkexec "$@"
    else
        die "need sudo or pkexec to plant the CA / DNS route"
    fi
}

clone_or_update() {
    local url="$1" dest="$2"
    shift 2
    if [ -d "$dest/.git" ]; then
        log "updating $(basename "$dest")"
        git -C "$dest" fetch --tags origin >/dev/null
        git -C "$dest" checkout "$REF" >/dev/null 2>&1 \
            || git -C "$dest" checkout main >/dev/null 2>&1 \
            || true
        git -C "$dest" pull --ff-only >/dev/null 2>&1 || true
    else
        log "cloning $(basename "$dest") ($REF, falling back to default branch)"
        mkdir -p "$(dirname "$dest")"
        if ! git clone --branch "$REF" "$@" "$url" "$dest" 2>/dev/null; then
            git clone "$@" "$url" "$dest"
        fi
    fi
}

ensure_deps() {
    local missing=()
    have git    || missing+=(git)
    have cc     || missing+=(cc)
    have make   || missing+=(make)
    have cmake  || missing+=(cmake)
    have pkg-config || missing+=(pkg-config)
    if [ "$os" = linux ]; then
        pkg-config --exists openssl 2>/dev/null || missing+=(libssl)
        pkg-config --exists sqlite3 2>/dev/null || missing+=(libsqlite3)
    fi
    [ ${#missing[@]} -eq 0 ] && return 0
    log "missing: ${missing[*]}"
    if [ "$os" = linux ] && have apt-get; then
        elevate apt-get install -y git build-essential cmake pkg-config libssl-dev libsqlite3-dev libnss3-tools
    elif [ "$os" = macos ]; then
        have brew || die "install Homebrew, then: brew install git cmake pkg-config openssl@3 sqlite"
        brew install git cmake pkg-config openssl@3 sqlite
    else
        die "install git, a C compiler, cmake, pkg-config, OpenSSL 3, sqlite3 and re-run"
    fi
}

# Boot daemons, not login agents: they come up at startup without a
# session, keep running after logout, and restart if they die. The
# process still runs as the installing user (the proxy is loopback-only
# and must not be root). HOME is pinned so ~/.pepenet CA files resolve.
install_file() {
    local src="$1" dest="$2"
    elevate cp "$src" "$dest"
    elevate chmod 644 "$dest"
}

write_linux_units() {
    local user gid tmp flags="" p
    user="$(id -un)"
    gid="$(id -gn)"
    tmp="$(mktemp -d)"
    local IFS=,
    for p in $PEER; do
        [ -n "$p" ] || continue
        flags="$flags --peer $p"
    done
    unset IFS
    cat > "$tmp/pepenet-dnsd.service" <<EOF
[Unit]
Description=PepeNet DNS resolver (.$TLD)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$user
Group=$gid
Environment=HOME=$HOME
WorkingDirectory=$HOME_DIR
ExecStart=$BIN_DIR/dnsd --db $HOME_DIR/$COIN.db --store $HOME_DIR/dns-$COIN.db --coin $COIN --suffix $TLD --dns-port $DNS_PORT --tls-redirect 127.0.0.1$flags
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    cat > "$tmp/pepenet-tls.service" <<EOF
[Unit]
Description=PepeNet DANE TLS proxy (.$TLD)
After=network-online.target pepenet-dnsd.service
Wants=network-online.target pepenet-dnsd.service

[Service]
Type=simple
User=$user
Group=$gid
Environment=HOME=$HOME
WorkingDirectory=$HOME_DIR
ExecStart=$BIN_DIR/pepenet-tls --tld $TLD serve --db $HOME_DIR/$COIN.db --store $HOME_DIR/dns-$COIN.db --listen 127.0.0.1 --port $PROXY_PORT
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    # drop a leftover user-unit from the first installer, if any
    systemctl --user disable --now pepenet-tls.service pepenet-dnsd.service >/dev/null 2>&1 || true
    install_file "$tmp/pepenet-dnsd.service" /etc/systemd/system/pepenet-dnsd.service
    install_file "$tmp/pepenet-tls.service"  /etc/systemd/system/pepenet-tls.service
    rm -rf "$tmp"
    elevate systemctl daemon-reload
    elevate systemctl enable --now pepenet-dnsd.service pepenet-tls.service
}

macos_plist() {
    local label="$1" log="$2"
    shift 2
    cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$label</string>
  <key>UserName</key><string>$(id -un)</string>
  <key>EnvironmentVariables</key><dict>
    <key>HOME</key><string>$HOME</string>
  </dict>
  <key>WorkingDirectory</key><string>$HOME_DIR</string>
  <key>ProgramArguments</key><array>
$(for a in "$@"; do printf '    <string>%s</string>\n' "$a"; done)
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$log</string>
  <key>StandardErrorPath</key><string>$log</string>
</dict></plist>
EOF
}

write_macos_agents() {
    local tmp="$HOME_DIR" p
    mkdir -p "$tmp"
    local dnsd_args=( "$BIN_DIR/dnsd" --db "$HOME_DIR/$COIN.db" --store "$HOME_DIR/dns-$COIN.db"
                      --coin "$COIN" --suffix "$TLD" --dns-port "$DNS_PORT"
                      --tls-redirect 127.0.0.1 )
    local IFS=,
    for p in $PEER; do
        [ -n "$p" ] || continue
        dnsd_args+=( --peer "$p" )
    done
    unset IFS
    macos_plist com.pepenet.dnsd "$HOME_DIR/dnsd.log" \
        "${dnsd_args[@]}" \
        > "$tmp/com.pepenet.dnsd.plist"
    macos_plist com.pepenet.tls "$HOME_DIR/tls.log" \
        "$BIN_DIR/pepenet-tls" --tld "$TLD" serve \
        --db "$HOME_DIR/$COIN.db" --store "$HOME_DIR/dns-$COIN.db" \
        --listen 127.0.0.1 --port "$PROXY_PORT" \
        > "$tmp/com.pepenet.tls.plist"
    # retire the login-only LaunchAgents from the first installer
    launchctl bootout "gui/$(id -u)/com.pepenet.dnsd" >/dev/null 2>&1 || true
    launchctl bootout "gui/$(id -u)/com.pepenet.tls" >/dev/null 2>&1 || true
    rm -f "$HOME/Library/LaunchAgents/com.pepenet.dnsd.plist" \
          "$HOME/Library/LaunchAgents/com.pepenet.tls.plist"
    install_file "$tmp/com.pepenet.dnsd.plist" /Library/LaunchDaemons/com.pepenet.dnsd.plist
    install_file "$tmp/com.pepenet.tls.plist"  /Library/LaunchDaemons/com.pepenet.tls.plist
    elevate launchctl bootout system/com.pepenet.dnsd >/dev/null 2>&1 || true
    elevate launchctl bootout system/com.pepenet.tls >/dev/null 2>&1 || true
    elevate launchctl bootstrap system /Library/LaunchDaemons/com.pepenet.dnsd.plist
    elevate launchctl bootstrap system /Library/LaunchDaemons/com.pepenet.tls.plist
}

stop_services() {
    if [ "$os" = linux ]; then
        elevate systemctl disable --now pepenet-tls.service pepenet-dnsd.service >/dev/null 2>&1 || true
        elevate rm -f /etc/systemd/system/pepenet-tls.service /etc/systemd/system/pepenet-dnsd.service
        elevate systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl --user disable --now pepenet-tls.service pepenet-dnsd.service >/dev/null 2>&1 || true
    else
        elevate launchctl bootout system/com.pepenet.tls >/dev/null 2>&1 || true
        elevate launchctl bootout system/com.pepenet.dnsd >/dev/null 2>&1 || true
        elevate rm -f /Library/LaunchDaemons/com.pepenet.tls.plist \
                      /Library/LaunchDaemons/com.pepenet.dnsd.plist
        launchctl bootout "gui/$(id -u)/com.pepenet.tls" >/dev/null 2>&1 || true
        launchctl bootout "gui/$(id -u)/com.pepenet.dnsd" >/dev/null 2>&1 || true
        rm -f "$HOME/Library/LaunchAgents/com.pepenet.tls.plist" \
              "$HOME/Library/LaunchAgents/com.pepenet.dnsd.plist"
    fi
}

do_uninstall() {
    log "stopping daemons"
    stop_services
    if [ -x "$SRC/pepenet-tls/install.sh" ]; then
        log "removing OS wiring (CA / DNS / redirect)"
        elevate "$SRC/pepenet-tls/install.sh" uninstall "$TLD" || true
    fi
    rm -f "$BIN_DIR/dnsd" "$BIN_DIR/pepenet-tls"
    log "left $HOME_DIR (chain db, zone store, source). rm -rf $HOME_DIR to wipe."
}

do_setup() {
    mkdir -p "$HOME_DIR" "$BIN_DIR" "$SRC"
    ensure_deps

    clone_or_update "$GH/namespace-indexer.git"  "$SRC/namespace-indexer" --recursive
    clone_or_update "$GH/namespace-protocol.git" "$SRC/namespace-protocol"
    clone_or_update "$GH/pepenet-mesh.git"       "$SRC/pepenet-mesh"
    clone_or_update "$GH/pepenet-dns.git"        "$SRC/pepenet-dns"
    clone_or_update "$GH/pepenet-tls.git"        "$SRC/pepenet-tls"

    # glibc + -std=c11 hides mkdtemp/fdopen; mesh pins _DEFAULT_SOURCE.
    # Harmless elsewhere.
    local posix="-std=c11 -D_DEFAULT_SOURCE -O2 -Wall -Wextra"
    log "building mesh (libsecp + libpepenetnet.a)"
    make -C "$SRC/pepenet-mesh" CFLAGS="$posix -Wshadow" -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)"
    log "building dnsd"
    make -C "$SRC/pepenet-dns" CFLAGS="$posix -Wshadow" dnsd
    log "building pepenet-tls"
    if [ "$os" = macos ]; then
        make -C "$SRC/pepenet-tls" pepenet-tls
    else
        make -C "$SRC/pepenet-tls" CFLAGS="$posix $(pkg-config --cflags openssl)" pepenet-tls
    fi

    cp -f "$SRC/pepenet-dns/dnsd" "$BIN_DIR/dnsd"
    cp -f "$SRC/pepenet-tls/pepenet-tls" "$BIN_DIR/pepenet-tls"
    chmod +x "$BIN_DIR/dnsd" "$BIN_DIR/pepenet-tls"

    log "ensuring the name-constrained .$TLD root"
    "$BIN_DIR/pepenet-tls" --tld "$TLD" gen-ca

    log "installing boot daemons (dnsd + pepenet-tls — Restart=always, survive reboot)"
    if [ "$os" = linux ]; then
        write_linux_units
    else
        write_macos_agents
    fi

    log "planting OS trust / DNS / :443 redirect (sudo/pkexec)"
    elevate "$SRC/pepenet-tls/install.sh" install "$TLD"

    cat <<EOF

.$TLD is live on this box.

  resolver  127.0.0.1:$DNS_PORT
  proxy     127.0.0.1:$PROXY_PORT
  data      $HOME_DIR
  binaries  $BIN_DIR

Open https://<name>.$TLD in a browser (quit+reopen Firefox if you use it).
Uninstall:  curl -fsSL https://raw.githubusercontent.com/$ORG/pepenet-tls/$REF/get.sh | bash -s -- uninstall
EOF
}

if [ "$ACTION" = uninstall ]; then
    do_uninstall
else
    do_setup
fi
