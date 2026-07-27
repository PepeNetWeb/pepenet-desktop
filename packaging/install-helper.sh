#!/bin/sh
# install-helper.sh — the PRIVILEGED half of PepeNet's web install, run via
# `osascript … with administrator privileges` from the DNS & Web tab. It does
# ONLY the steps that need root:
#   1. /etc/resolver/<tld>  → route *.<tld> DNS at the local resolver
#   2. system PAC → http://127.0.0.1:<pac-port>/proxy.pac (every network
#      service) — the PRIMARY browser route: the PAC steers *.<tld> at the
#      app's CONNECT front door, so browsers work without DNS, without :443,
#      and regardless of pf. Foreign PACs (corporate) are never clobbered.
#   3. pf rdr :443 → :<proxy-port> — best-effort legacy route (loopback rdr is
#      unreliable on macOS; kept for non-PAC-honoring clients like curl).
# The root-CA trust is a login-keychain op and is done UNPRIVILEGED, in-process
# (trust_install), so it never appears here. Firefox NSS is deferred.
#
#   install-helper.sh install   <tld> --dns-port N --proxy-port N --pac-port N
#   install-helper.sh uninstall <tld>
#   install-helper.sh status    <tld>          (no root needed; prints probes)
set -eu

CMD="${1:-}"; TLD="${2:-pep}"
LOOPBACK="127.0.0.1"
DNS_PORT="15353"; PROXY_PORT="8443"; PAC_PORT="8444"
shift 2 2>/dev/null || true
while [ $# -gt 0 ]; do
    case "$1" in
        --dns-port)   DNS_PORT="$2";   shift 2 ;;
        --proxy-port) PROXY_PORT="$2"; shift 2 ;;
        --pac-port)   PAC_PORT="$2";   shift 2 ;;
        *) shift ;;
    esac
done
PAC_URL="http://$LOOPBACK:$PAC_PORT/proxy.pac"

RESOLVER="/etc/resolver/$TLD"
PF_ANCHOR="/etc/pf.anchors/pepenet-$TLD"
PF_TOKEN="# pepenet-$TLD"
# boot re-arm: macOS loads /etc/pf.conf at boot but leaves pf DISABLED, and
# pfctl -E does not survive a reboot — this daemon re-runs f+E at load
PF_DAEMON_LABEL="pepenet-pf-$TLD"
PF_DAEMON="/Library/LaunchDaemons/$PF_DAEMON_LABEL.plist"

pf_rule() {
    echo "rdr pass on lo0 inet proto tcp from any to $LOOPBACK port 443 -> $LOOPBACK port $PROXY_PORT"
}

# ── system PAC (networksetup, per network service) ────────────────────────────
# Service names may contain spaces; the listing's first line is a legend and
# disabled services carry a leading '*'. getautoproxyurl prints "URL: <u>" —
# "(null)" when unset. A foreign, enabled PAC is left alone (a corporate PAC
# outranks us — the resolver+pf route still covers those machines).
pac_services() {
    networksetup -listallnetworkservices 2>/dev/null | tail -n +2 | sed 's/^\*//'
}
pac_install() {
    pac_services | while IFS= read -r svc; do
        [ -n "$svc" ] || continue
        cur=$(networksetup -getautoproxyurl "$svc" 2>/dev/null | awk -F': ' '/^URL/{print $2}' || true)
        if [ -n "$cur" ] && [ "$cur" != "(null)" ] && [ "$cur" != "$PAC_URL" ]; then
            en=$(networksetup -getautoproxyurl "$svc" 2>/dev/null | awk -F': ' '/^Enabled/{print $2}' || true)
            if [ "$en" = "Yes" ]; then
                echo "  [skip] '$svc' has a foreign PAC ($cur) — leaving it" >&2
                continue
            fi
        fi
        networksetup -setautoproxyurl "$svc" "$PAC_URL" 2>/dev/null || true
    done
}
pac_uninstall() {
    pac_services | while IFS= read -r svc; do
        [ -n "$svc" ] || continue
        cur=$(networksetup -getautoproxyurl "$svc" 2>/dev/null | awk -F': ' '/^URL/{print $2}' || true)
        [ "$cur" = "$PAC_URL" ] && networksetup -setautoproxystate "$svc" off 2>/dev/null || true
    done
}

# remove every pf.conf line of ours — this TLD or a stale sibling, the old
# 3-line EOF block or the new tagged lines. The names cannot appear in the
# stock file, so a bare substring match is safe.
pf_strip() {
    grep -v -e 'pepenet-' -e 'pepenet-tls-' /etc/pf.conf > /etc/pf.conf.pepenet-tmp \
        && mv /etc/pf.conf.pepenet-tmp /etc/pf.conf
}

case "$CMD" in
install)
    [ "$(id -u)" = "0" ] || { echo "install needs root" >&2; exit 1; }
    mkdir -p /etc/resolver
    printf 'nameserver %s\nport %s\n' "$LOOPBACK" "$DNS_PORT" > "$RESOLVER"

    # the primary browser route — register the PAC before touching pf, so a
    # pf failure below can no longer take the whole browser path with it
    pac_install

    pf_rule > "$PF_ANCHOR"
    # pf.conf ordering matters: rdr-anchor is a TRANSLATION rule and must sit
    # BEFORE the filtering section (anchor "com.apple/*"). The old append-at-EOF
    # made pfctl -f reject the whole file ("Rules must be in order"), silently —
    # the redirect never loaded. Repair: strip every line of ours (any pepenet-*
    # / pepenet-tls-* block, old or new format), then splice the rdr-anchor in
    # right after the system's rdr-anchor line; the load directive goes at EOF
    # (directives are order-insensitive; the stock file keeps its own load last).
    pf_strip
    awk -v tld="$TLD" -v anchor="$PF_ANCHOR" '
        { print }
        /^rdr-anchor "com\.apple\/\*"/ {
            print "rdr-anchor \"pepenet-" tld "\" " "'"$PF_TOKEN"'"
        }
        END {
            print "load anchor \"pepenet-" tld "\" from \"" anchor "\" " "'"$PF_TOKEN"'"
        }
    ' /etc/pf.conf > /etc/pf.conf.pepenet-tmp && mv /etc/pf.conf.pepenet-tmp /etc/pf.conf
    # best-effort: the PAC route above is the one browsers ride; pf only backs
    # up non-PAC clients (curl, dig-driven tools) — never fail the install on it
    if ! pfctl -f /etc/pf.conf; then
        echo "[WARN] pfctl -f rejected /etc/pf.conf — pf redirect not active (PAC route unaffected)" >&2
    fi
    pfctl -E 2>/dev/null || true

    # boot persistence for the redirect
    cat > "$PF_DAEMON" <<PFEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$PF_DAEMON_LABEL</string>
  <key>ProgramArguments</key><array>
    <string>/bin/sh</string><string>-c</string>
    <string>/sbin/pfctl -f /etc/pf.conf; /sbin/pfctl -E</string>
  </array>
  <key>RunAtLoad</key><true/>
</dict></plist>
PFEOF
    chown root:wheel "$PF_DAEMON"
    chmod 644 "$PF_DAEMON"
    launchctl bootstrap system "$PF_DAEMON" 2>/dev/null || true
    echo "installed resolver+PAC(+pf) for .$TLD"
    ;;
uninstall)
    [ "$(id -u)" = "0" ] || { echo "uninstall needs root" >&2; exit 1; }
    pac_uninstall
    launchctl bootout "system/$PF_DAEMON_LABEL" 2>/dev/null || true
    rm -f "$RESOLVER" "$PF_ANCHOR" "$PF_DAEMON"
    pf_strip
    pfctl -f /etc/pf.conf 2>/dev/null || true
    echo "removed resolver+PAC(+pf) for .$TLD"
    ;;
status)
    [ -f "$RESOLVER" ] && echo "resolver=1" || echo "resolver=0"
    if scutil --proxy | grep -q "$PAC_URL"; then echo "pac=1"; else echo "pac=0"; fi
    if pfctl -sn 2>/dev/null | grep -q "port $PROXY_PORT"; then echo "pf=1"; else echo "pf=0"; fi
    ;;
*)
    echo "usage: install-helper.sh {install <tld> --dns-port N --proxy-port N --pac-port N | uninstall <tld> | status <tld>}" >&2
    exit 2
    ;;
esac
