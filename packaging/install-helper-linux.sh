#!/bin/sh
# install-helper-linux.sh — the PRIVILEGED half of PepeNet's web install, run
# via `pkexec` from the DNS & Web tab. It does ONLY the steps that need root:
#   1. system CA store (update-ca-certificates / update-ca-trust) so p11-kit,
#      Chromium, Firefox enterprise-roots, and curl all see the name-constrained
#      root. The unprivileged NSS db is done in-process (trust_install).
#   2. systemd-resolved split-DNS on lo: *.<tld> → 127.0.0.1:<dns-port>. Must
#      NOT replace the box's global resolvers (never a global DNS=).
#   3. nftables rdr 127.0.0.1:443 → :<proxy-port> — best-effort legacy route
#      (PAC is the PRIMARY browser path and is unprivileged, in-process).
#
#   install-helper-linux.sh install   <tld> --dns-port N --proxy-port N --pac-port N --cert PATH
#   install-helper-linux.sh uninstall <tld>
#   install-helper-linux.sh status    <tld>
set -eu

CMD="${1:-}"; TLD="${2:-pepe}"
LOOPBACK="127.0.0.1"
DNS_PORT="15353"; PROXY_PORT="8443"; PAC_PORT="8444"
CERT=""
shift 2 2>/dev/null || true
while [ $# -gt 0 ]; do
    case "$1" in
        --dns-port)   DNS_PORT="$2";   shift 2 ;;
        --proxy-port) PROXY_PORT="$2"; shift 2 ;;
        --pac-port)   PAC_PORT="$2";   shift 2 ;;
        --cert)       CERT="$2";       shift 2 ;;
        *) shift ;;
    esac
done

UNIT="pepenet-web-$TLD.service"
UNIT_PATH="/etc/systemd/system/$UNIT"
NFT_DIR="/etc/pepenet"
NFT_FILE="$NFT_DIR/nft-$TLD.nft"
CA_DEB="/usr/local/share/ca-certificates/pepenet-$TLD.crt"
CA_FED="/etc/pki/ca-trust/source/anchors/pepenet-$TLD.crt"

if [ -z "$CERT" ]; then
    RUID="${PKEXEC_UID:-${SUDO_UID:-}}"
    if [ -n "$RUID" ]; then
        RHOME="$(getent passwd "$RUID" | cut -d: -f6)"
        CERT="${RHOME:-/root}/.pepenet/pepenet-root-$TLD.crt"
    fi
fi

ca_install() {
    [ -n "$CERT" ] && [ -f "$CERT" ] || { echo "no root cert (--cert)" >&2; return 1; }
    if [ -d /usr/local/share/ca-certificates ] && command -v update-ca-certificates >/dev/null 2>&1; then
        cp "$CERT" "$CA_DEB"
        chmod 644 "$CA_DEB"
        update-ca-certificates >/dev/null
    elif command -v update-ca-trust >/dev/null 2>&1; then
        mkdir -p /etc/pki/ca-trust/source/anchors
        cp "$CERT" "$CA_FED"
        chmod 644 "$CA_FED"
        update-ca-trust extract
    else
        echo "[WARN] no update-ca-certificates / update-ca-trust" >&2
    fi
}

ca_uninstall() {
    rm -f "$CA_DEB" "$CA_FED"
    command -v update-ca-certificates >/dev/null 2>&1 && update-ca-certificates >/dev/null 2>&1 || true
    command -v update-ca-trust >/dev/null 2>&1 && update-ca-trust extract >/dev/null 2>&1 || true
}

write_nft() {
    mkdir -p "$NFT_DIR"
    cat > "$NFT_FILE" <<EOF
table ip pepenet-$TLD {
    chain output {
        type nat hook output priority -100;
        ip daddr $LOOPBACK tcp dport 443 redirect to :$PROXY_PORT
    }
}
EOF
}

write_unit() {
    cat > "$UNIT_PATH" <<EOF
[Unit]
Description=PepeNet .$TLD split-DNS + loopback :443 redirect
After=systemd-resolved.service
Wants=systemd-resolved.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/resolvectl dns lo $LOOPBACK:$DNS_PORT
ExecStart=/usr/bin/resolvectl domain lo ~$TLD
-ExecStart=/usr/sbin/nft -f $NFT_FILE
-ExecStop=/usr/bin/resolvectl revert lo
-ExecStop=/usr/sbin/nft delete table ip pepenet-$TLD

[Install]
WantedBy=multi-user.target
EOF
}

case "$CMD" in
install)
    [ "$(id -u)" = "0" ] || { echo "install needs root" >&2; exit 1; }
    ca_install
    write_nft
    write_unit
    if command -v resolvectl >/dev/null 2>&1; then
        resolvectl dns lo "$LOOPBACK:$DNS_PORT" || echo "[WARN] resolvectl dns lo failed" >&2
        resolvectl domain lo "~$TLD" || echo "[WARN] resolvectl domain lo failed" >&2
    fi
    if command -v nft >/dev/null 2>&1; then
        nft delete table ip pepenet-$TLD >/dev/null 2>&1 || true
        nft -f "$NFT_FILE" || echo "[WARN] nft failed — PAC route unaffected" >&2
    fi
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload
        systemctl enable --now "$UNIT" >/dev/null 2>&1 || \
            echo "[WARN] systemctl enable $UNIT failed" >&2
    fi
    echo "installed resolver+CA(+nft) for .$TLD"
    ;;
uninstall)
    [ "$(id -u)" = "0" ] || { echo "uninstall needs root" >&2; exit 1; }
    ca_uninstall
    command -v systemctl >/dev/null 2>&1 && systemctl disable --now "$UNIT" >/dev/null 2>&1 || true
    rm -f "$UNIT_PATH" "$NFT_FILE"
    rmdir "$NFT_DIR" 2>/dev/null || true
    command -v resolvectl >/dev/null 2>&1 && resolvectl revert lo 2>/dev/null || true
    command -v nft >/dev/null 2>&1 && nft delete table ip pepenet-$TLD 2>/dev/null || true
    command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload || true
    echo "removed resolver+CA(+nft) for .$TLD"
    ;;
status)
    [ -f "$CA_DEB" ] || [ -f "$CA_FED" ] && echo "ca=1" || echo "ca=0"
    if command -v resolvectl >/dev/null 2>&1 && resolvectl domain lo 2>/dev/null | grep -q "$TLD"; then
        echo "resolver=1"
    else
        echo "resolver=0"
    fi
    if command -v nft >/dev/null 2>&1 && nft list table ip pepenet-$TLD >/dev/null 2>&1; then
        echo "nft=1"
    else
        echo "nft=0"
    fi
    ;;
*)
    echo "usage: install-helper-linux.sh {install <tld> --dns-port N --proxy-port N --pac-port N --cert PATH | uninstall <tld> | status <tld>}" >&2
    exit 2
    ;;
esac
