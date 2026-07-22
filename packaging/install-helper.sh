#!/bin/sh
# install-helper.sh — the PRIVILEGED half of PepeNet's web install, run via
# `osascript … with administrator privileges` from the DNS & Web tab. It does
# ONLY the two steps that need root:
#   1. /etc/resolver/<tld>  → route *.<tld> DNS at the local resolver
#   2. pf rdr :443 → :<proxy-port>  → steer the browser at the local proxy
# The root-CA trust is a login-keychain op and is done UNPRIVILEGED, in-process
# (trust_install), so it never appears here. Firefox NSS is deferred.
#
#   install-helper.sh install   <tld> --dns-port N --proxy-port N
#   install-helper.sh uninstall <tld>
#   install-helper.sh status    <tld>          (no root needed; prints probes)
set -eu

CMD="${1:-}"; TLD="${2:-pep}"
LOOPBACK="127.0.0.1"
DNS_PORT="15353"; PROXY_PORT="8443"
shift 2 2>/dev/null || true
while [ $# -gt 0 ]; do
    case "$1" in
        --dns-port)   DNS_PORT="$2";   shift 2 ;;
        --proxy-port) PROXY_PORT="$2"; shift 2 ;;
        *) shift ;;
    esac
done

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
    if ! pfctl -f /etc/pf.conf; then
        echo "[FAIL] pfctl -f rejected /etc/pf.conf — redirect NOT active" >&2
        exit 1
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
    echo "installed resolver+pf for .$TLD (pf re-arms at boot)"
    ;;
uninstall)
    [ "$(id -u)" = "0" ] || { echo "uninstall needs root" >&2; exit 1; }
    launchctl bootout "system/$PF_DAEMON_LABEL" 2>/dev/null || true
    rm -f "$RESOLVER" "$PF_ANCHOR" "$PF_DAEMON"
    pf_strip
    pfctl -f /etc/pf.conf 2>/dev/null || true
    echo "removed resolver+pf for .$TLD"
    ;;
status)
    [ -f "$RESOLVER" ] && echo "resolver=1" || echo "resolver=0"
    if pfctl -sn 2>/dev/null | grep -q "port $PROXY_PORT"; then echo "pf=1"; else echo "pf=0"; fi
    ;;
*)
    echo "usage: install-helper.sh {install <tld> --dns-port N --proxy-port N | uninstall <tld> | status <tld>}" >&2
    exit 2
    ;;
esac
