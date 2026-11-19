#!/bin/sh
# install.sh — the one privileged step that makes `.doge`/`.pepe` HTTPS Just Work
# in a browser on macOS. Slice 4 (DESIGN.md §7). Idempotent; has an uninstall.
#
# Three things, for ONE TLD (this box is a doge box OR a pepe box, never both):
#   1. trust the name-constrained root CA in the login keychain (as the user,
#      GUI auth = consent) — bounded to just this TLD, see DESIGN.md §2;
#   2. write /etc/resolver/<tld> so the system routes `*.<tld>` DNS to dnsd
#      (127.0.0.1 on the DNS port);
#   3. add a pf redirect 127.0.0.1:443 -> 127.0.0.1:<proxy-port> so the browser's
#      HTTPS lands on the unprivileged proxy (which never needs root / :443).
#
# dnsd itself must run with `--tls-redirect 127.0.0.1` so DANE names answer the
# loopback A; and `pepenet-tls serve` must be running on <proxy-port>. This
# script wires the OS; it does not start those daemons.
#
# Usage:
#   sudo ./install.sh install   doge|pepe   [--dns-port 15353] [--proxy-port 8443]
#   sudo ./install.sh uninstall doge|pepe
#
# Verified live (2026-07-07, .pepe): Safari shows the padlock end-to-end. Two
# things the first live run taught us, now baked in:
#   - DNS default is 15353, NOT 5353: 5353 is Bonjour/mDNS's port, and macOS
#     mDNSResponder won't forward a scoped /etc/resolver to its own mDNS port
#     (the query never reaches dnsd), so name resolution silently fails.
#   - Firefox ignores the macOS keychain (uses its own NSS store). Step 4 flips
#     security.enterprise_roots.enabled via user.js so it trusts keychain roots.
#   - pf CAVEAT: macOS pf loopback rdr (:443 -> :proxy) is unreliable. If the
#     browser resolves but "can't connect", run the proxy directly on :443 as
#     root instead (see the note printed after install).

set -eu

# Linux has no keychain / /etc/resolver / pf — those analogues live in
# install-linux.sh (nssdb + ca-certificates + systemd-resolved + nftables).
if [ "$(uname -s)" = "Linux" ]; then
    exec "$(cd "$(dirname "$0")" && pwd)/install-linux.sh" "$@"
fi

ACTION="${1:-}"
TLD="${2:-}"
DNS_PORT=15353
PROXY_PORT=8443
LOOPBACK=127.0.0.1

shift 2 2>/dev/null || { echo "usage: sudo $0 {install|uninstall} <doge|pepe> [opts]" >&2; exit 2; }
while [ $# -gt 0 ]; do
    case "$1" in
        --dns-port)   DNS_PORT="$2";   shift 2 ;;
        --proxy-port) PROXY_PORT="$2"; shift 2 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

case "$TLD" in doge|pepe) ;; *)
    echo "TLD must be 'doge' or 'pepe' (this box serves exactly one)" >&2; exit 2 ;;
esac
case "$ACTION" in install|uninstall) ;; *)
    echo "action must be 'install' or 'uninstall'" >&2; exit 2 ;;
esac

if [ "$(id -u)" != "0" ]; then
    echo "must run as root (sudo) — it writes /etc/resolver and reloads pf" >&2
    exit 1
fi

# The unprivileged user we drop to for the login-keychain CA step.
RUSER="${SUDO_USER:-$(id -un)}"
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/pepenet-tls"

RESOLVER="/etc/resolver/$TLD"
PF_ANCHOR="/etc/pf.anchors/pepenet-tls-$TLD"
PF_TOKEN="# pepenet-tls-$TLD"        # marker line we add to /etc/pf.conf

pf_rule() {
    # rdr for locally-originated connections to 127.0.0.1:443 → the proxy port.
    echo "rdr pass on lo0 inet proto tcp from any to $LOOPBACK port 443 -> $LOOPBACK port $PROXY_PORT"
}

# Firefox uses its own NSS trust store, not the macOS keychain — so a keychain
# root is invisible to it (SEC_ERROR_UNKNOWN_ISSUER). Rather than depend on
# `certutil` (the nss brew pkg), we flip security.enterprise_roots.enabled, which
# makes Firefox additionally trust roots from the OS keychain (where our .$TLD
# root already lives). We write it to user.js (read at every startup, never
# rewritten by Firefox — unlike prefs.js) in each profile, as the real user.
FF_MARK="// pepenet-tls: trust macOS-keychain roots (incl. the .$TLD root CA)"
FF_PREF='user_pref("security.enterprise_roots.enabled", true);'

firefox_profiles() {
    RHOME="$(eval echo "~$RUSER")"
    echo "$RHOME/Library/Application Support/Firefox/Profiles"
}

firefox_install() {
    pd="$(firefox_profiles)"
    [ -d "$pd" ] || { echo "   (no Firefox profiles — skipping)"; return 0; }
    n=0
    for prof in "$pd"/*/; do
        [ -d "$prof" ] || continue
        uj="${prof}user.js"
        if sudo -u "$RUSER" grep -qs 'security.enterprise_roots.enabled' "$uj" 2>/dev/null; then
            continue
        fi
        printf '%s\n%s\n' "$FF_MARK" "$FF_PREF" | sudo -u "$RUSER" tee -a "$uj" >/dev/null
        n=$((n + 1))
    done
    echo "   enabled enterprise roots in $n Firefox profile(s) — restart Firefox to apply"
}

firefox_uninstall() {
    pd="$(firefox_profiles)"
    [ -d "$pd" ] || return 0
    for prof in "$pd"/*/; do
        uj="${prof}user.js"
        [ -f "$uj" ] || continue
        # remove our marker line + the pref line that follows it
        sudo -u "$RUSER" sed -i '' '/pepenet-tls: trust macOS-keychain roots/,+1d' "$uj" 2>/dev/null || true
    done
    echo "   removed the enterprise-roots pref from Firefox profiles (restart Firefox)"
}

do_install() {
    [ -x "$BIN" ] || { echo "build first: (cd $HERE && make pepenet-tls)"; exit 1; }

    echo "==> 1/4 trusting the name-constrained .$TLD root (as $RUSER; GUI auth expected)"
    sudo -u "$RUSER" "$BIN" --tld "$TLD" install-ca

    echo "==> 2/4 routing *.$TLD DNS to dnsd at $LOOPBACK#$DNS_PORT ($RESOLVER)"
    mkdir -p /etc/resolver
    printf 'nameserver %s\nport %s\n' "$LOOPBACK" "$DNS_PORT" > "$RESOLVER"

    echo "==> 3/4 pf redirect $LOOPBACK:443 -> $LOOPBACK:$PROXY_PORT ($PF_ANCHOR)"
    pf_rule > "$PF_ANCHOR"
    if ! grep -q "$PF_TOKEN" /etc/pf.conf; then
        {
            echo "$PF_TOKEN"
            echo "rdr-anchor \"pepenet-tls-$TLD\""
            echo "load anchor \"pepenet-tls-$TLD\" from \"$PF_ANCHOR\""
        } >> /etc/pf.conf
    fi
    # (re)load pf; -E enables it and keeps a token so we don't fight the firewall UI.
    # Do NOT swallow the error: macOS requires rdr-anchor to precede filter rules,
    # and loopback rdr is flaky — if this warns, use the :443 fallback below.
    pfctl -f /etc/pf.conf || echo "   [WARN] pfctl -f failed — see the :443 fallback note below"
    pfctl -E 2>/dev/null || true

    echo "==> 4/4 Firefox trust (its own NSS store, not the keychain)"
    firefox_install

    cat <<EOF

installed for .$TLD. To go live:
  1. run dnsd with:   --tls-redirect $LOOPBACK --suffix $TLD --dns-port $DNS_PORT
  2. run the proxy:   $BIN --tld $TLD serve --db <indexer.db> --store <carrier.db> --port $PROXY_PORT
  3. verify:          curl -v https://<name>.$TLD/    (expect the padlock, no CA warning)
  4. Firefox: fully quit + reopen it (enterprise roots are read at startup)

if the browser resolves but "can't connect" (pf loopback rdr is unreliable on
macOS), skip pf and run the proxy directly on :443 as root instead:
  sudo env HOME="\$HOME" $BIN --tld $TLD serve --db <indexer.db> --store <carrier.db> --listen $LOOPBACK --port 443

manual verification checklist (first run):
  - scutil --dns | grep -A2 $TLD                       # scoped resolver present
  - dscacheutil -q host -a name <name>.$TLD            # SYSTEM resolves → $LOOPBACK (what the browser uses)
  - dig @$LOOPBACK -p $DNS_PORT <name>.$TLD A          # dnsd answers $LOOPBACK for DANE names
  - pfctl -sn | grep $PROXY_PORT                       # rdr rule loaded (if using pf)
EOF
}

do_uninstall() {
    echo "==> removing .$TLD root trust (as $RUSER)"
    [ -x "$BIN" ] && sudo -u "$RUSER" "$BIN" --tld "$TLD" uninstall-ca || true

    echo "==> removing $RESOLVER"
    rm -f "$RESOLVER"

    echo "==> reverting Firefox enterprise-roots pref"
    firefox_uninstall

    echo "==> removing pf anchor + /etc/pf.conf lines"
    rm -f "$PF_ANCHOR"
    if grep -q "$PF_TOKEN" /etc/pf.conf; then
        # drop our token line + the two anchor lines that follow it
        sed -i '' "/$PF_TOKEN/,+2d" /etc/pf.conf 2>/dev/null || \
            sed -i "/$PF_TOKEN/,+2d" /etc/pf.conf
    fi
    pfctl -f /etc/pf.conf 2>/dev/null || true

    echo "done. (pf left enabled; disable with 'sudo pfctl -d' if nothing else needs it.)"
}

case "$ACTION" in
    install)   do_install ;;
    uninstall) do_uninstall ;;
esac
