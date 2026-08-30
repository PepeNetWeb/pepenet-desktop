#!/bin/sh
# install-helper-linux.sh — the PRIVILEGED half of PepeNet's web install, run
# via pkexec (or sudo if pkexec is missing) from the DNS & Web tab. It does
# ONLY the steps that need root:
#   1. system CA store (update-ca-certificates / update-ca-trust) so p11-kit,
#      Chromium, Firefox enterprise-roots, and curl all see the name-constrained
#      root. The unprivileged NSS db is done in-process (trust_install).
#   2. systemd-resolved split-DNS on dummy pn-<tld> (not lo): *.<tld> →
#      127.0.0.1:<dns-port>. Must NOT replace the box's global resolvers.
#   3. nftables rdr 127.0.0.1:443 → :<proxy-port> — best-effort legacy route
#      (PAC is the PRIMARY browser path and is unprivileged, in-process).
#   4. Snap Firefox: copy the PEM under /etc/firefox/policies (the sandbox can
#      read that, not the host p11-kit store) and exclude .<tld> from DoH.
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
IFACE="pn-$TLD"
SPLIT_FILE="$NFT_DIR/split-dns-$TLD.sh"
NM_UNMANAGED="/etc/NetworkManager/conf.d/pepenet-$TLD-unmanaged.conf"
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

write_split_dns() {
    mkdir -p "$NFT_DIR"
    cat > "$SPLIT_FILE" <<EOF
#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
IFACE=$IFACE
ADDR=169.254.7.53/32
DNS=$LOOPBACK:$DNS_PORT
DOMAIN=~$TLD
NM_CONF=$NM_UNMANAGED
case "\${1:-apply}" in
stop)
    resolvectl revert "\$IFACE" >/dev/null 2>&1 || true
    resolvectl revert lo >/dev/null 2>&1 || true
    ip link del "\$IFACE" >/dev/null 2>&1 || true
    rm -f "\$NM_CONF"
    command -v nmcli >/dev/null 2>&1 && nmcli general reload >/dev/null 2>&1 || true
    ;;
*)
    if [ -d /etc/NetworkManager/conf.d ]; then
        printf '[keyfile]\\nunmanaged-devices=interface-name:%s\\n' "\$IFACE" > "\$NM_CONF"
        command -v nmcli >/dev/null 2>&1 && nmcli general reload >/dev/null 2>&1 || true
    fi
    if ! ip link show "\$IFACE" >/dev/null 2>&1; then
        modprobe dummy >/dev/null 2>&1 || true
        ip link add "\$IFACE" type dummy
    fi
    ip addr replace "\$ADDR" dev "\$IFACE"
    ip link set "\$IFACE" up
    resolvectl revert lo >/dev/null 2>&1 || true
    resolvectl dns "\$IFACE" "\$DNS"
    resolvectl domain "\$IFACE" "\$DOMAIN"
    resolvectl default-route "\$IFACE" false >/dev/null 2>&1 || true
    ;;
esac
EOF
    chmod 755 "$SPLIT_FILE"
}

# Same plant as pepenet-tls/install-linux.sh. Snap Firefox ignores the host
# CA store; /etc/firefox is visible via firefox:etc-firefox.
firefox_policies() {
    [ -n "$CERT" ] && [ -f "$CERT" ] || return 0
    mkdir -p /etc/firefox/policies/certificates
    cp "$CERT" "/etc/firefox/policies/certificates/pepenet-$TLD.crt"
    chmod 644 "/etc/firefox/policies/certificates/pepenet-$TLD.crt"
    POL=/etc/firefox/policies/policies.json
    CERT_POL="/etc/firefox/policies/certificates/pepenet-$TLD.crt"
    if command -v python3 >/dev/null 2>&1; then
        CERT_POL="$CERT_POL" TLD="$TLD" POL="$POL" python3 - <<'PY'
import json, os
path, cert, tld = os.environ["POL"], os.environ["CERT_POL"], os.environ["TLD"]
data = {"policies": {}}
if os.path.exists(path):
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception:
        data = {"policies": {}}
p = data.setdefault("policies", {})
certs = p.setdefault("Certificates", {})
certs["ImportEnterpriseRoots"] = True
inst = certs.setdefault("Install", [])
if cert not in inst:
    inst.append(cert)
doh = p.setdefault("DNSOverHTTPS", {})
if "Enabled" not in doh:
    doh["Enabled"] = True
ex = doh.setdefault("ExcludedDomains", [])
if tld not in ex:
    ex.append(tld)
doh["Fallback"] = True
os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, "w") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
PY
    else
        cat > "$POL" <<EOF
{
  "policies": {
    "Certificates": {
      "ImportEnterpriseRoots": true,
      "Install": ["$CERT_POL"]
    },
    "DNSOverHTTPS": {
      "Enabled": true,
      "ExcludedDomains": ["$TLD"],
      "Fallback": true
    }
  }
}
EOF
    fi
}

firefox_policies_uninstall() {
    rm -f "/etc/firefox/policies/certificates/pepenet-$TLD.crt"
    POL=/etc/firefox/policies/policies.json
    [ -f "$POL" ] && command -v python3 >/dev/null 2>&1 || return 0
    CERT_POL="/etc/firefox/policies/certificates/pepenet-$TLD.crt" TLD="$TLD" POL="$POL" python3 - <<'PY'
import json, os
path, cert, tld = os.environ["POL"], os.environ["CERT_POL"], os.environ["TLD"]
try:
    with open(path) as f:
        data = json.load(f)
except Exception:
    raise SystemExit
p = data.get("policies") or {}
certs = p.get("Certificates") or {}
inst = [x for x in certs.get("Install") or [] if x != cert]
if inst:
    certs["Install"] = inst
    p["Certificates"] = certs
else:
    p.pop("Certificates", None)
doh = p.get("DNSOverHTTPS") or {}
ex = [x for x in doh.get("ExcludedDomains") or [] if x != tld]
if ex:
    doh["ExcludedDomains"] = ex
    p["DNSOverHTTPS"] = doh
elif doh:
    doh.pop("ExcludedDomains", None)
    if list(doh.keys()) <= {"Enabled", "Fallback"}:
        p.pop("DNSOverHTTPS", None)
data["policies"] = p
if p:
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
else:
    os.remove(path)
PY
}

write_unit() {
    cat > "$UNIT_PATH" <<EOF
[Unit]
Description=PepeNet .$TLD split-DNS + loopback :443 redirect
After=systemd-resolved.service NetworkManager.service
Wants=systemd-resolved.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$SPLIT_FILE
ExecStart=-/usr/sbin/nft -f $NFT_FILE
ExecStop=$SPLIT_FILE stop
ExecStop=-/usr/sbin/nft delete table ip pepenet-$TLD

[Install]
WantedBy=multi-user.target
EOF
}

case "$CMD" in
install)
    [ "$(id -u)" = "0" ] || { echo "install needs root" >&2; exit 1; }
    ca_install
    write_nft
    write_split_dns
    write_unit
    if [ -x "$SPLIT_FILE" ]; then
        "$SPLIT_FILE" || echo "[WARN] split-DNS apply failed" >&2
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
    firefox_policies
    echo "installed resolver+CA(+nft) for .$TLD"
    ;;
uninstall)
    [ "$(id -u)" = "0" ] || { echo "uninstall needs root" >&2; exit 1; }
    ca_uninstall
    command -v systemctl >/dev/null 2>&1 && systemctl disable --now "$UNIT" >/dev/null 2>&1 || true
    [ -x "$SPLIT_FILE" ] && "$SPLIT_FILE" stop || true
    rm -f "$UNIT_PATH" "$NFT_FILE" "$SPLIT_FILE" "$NM_UNMANAGED"
    rmdir "$NFT_DIR" 2>/dev/null || true
    command -v resolvectl >/dev/null 2>&1 && resolvectl revert lo 2>/dev/null || true
    command -v nft >/dev/null 2>&1 && nft delete table ip pepenet-$TLD 2>/dev/null || true
    command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload || true
    firefox_policies_uninstall
    echo "removed resolver+CA(+nft) for .$TLD"
    ;;
status)
    [ -f "$CA_DEB" ] || [ -f "$CA_FED" ] && echo "ca=1" || echo "ca=0"
    if command -v resolvectl >/dev/null 2>&1 && resolvectl domain "$IFACE" 2>/dev/null | grep -q "$TLD"; then
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
