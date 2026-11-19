#!/bin/sh
# gd_node_test.sh — greatdane-node black-box checks (dane-01..08).
#   ./gd_node_test.sh [path/to/greatdane-node]
# MUST run in a private network namespace so nothing touches the host's
# ports (8443/8444/8445/15353) or network:  unshare -rn sh -c 'ip link set lo up && ./gd_node_test.sh'
# Never uses ~/.pepenet: every run gets its own --data under mktemp.
set -u
NODE=${1:-$(dirname "$0")/../build/greatdane-node}
[ -x "$NODE" ] || { echo "gd_node_test: SKIP — no $NODE (cmake --build build --target greatdane-node)"; exit 0; }
if [ -z "${GD_TEST_NETNS_OK:-}" ] && [ "$(cat /proc/self/net/dev 2>/dev/null | tail -n +3 | grep -vc ' lo:')" != "0" ]; then
    echo "gd_node_test: refusing to run outside a private netns (see header)"; exit 1
fi
ok=0; bad=0
check() { if [ "$1" = 0 ]; then ok=$((ok+1)); echo "ok   $2"; else bad=$((bad+1)); echo "FAIL $2"; fi; }
T=$(mktemp -d /tmp/gd_node_test.XXXXXX)
trap 'kill $HOLD $NPID 2>/dev/null; rm -rf "$T"' EXIT INT TERM
HOLD=; NPID=

# run_node <tag> <seconds> [env...]: node on --stdio, stdout -> $T/<tag>.out
run_node() {
    tag=$1; secs=$2; shift 2
    mkfifo "$T/$tag.in"
    # shellcheck disable=SC2086
    env "$@" "$NODE" --data "$T/$tag" --only pep --ephemeral-ports --dane-api --stdio ${NODE_ARGS:-} \
        < "$T/$tag.in" > "$T/$tag.out" 2> "$T/$tag.err" &
    NPID=$!
    exec 9> "$T/$tag.in"                  # hold stdin open: node lives while we do
    i=0; while [ $i -lt $((secs*10)) ]; do
        grep -q '"event":"status"' "$T/$tag.out" 2>/dev/null && \
          [ "$(grep -c '"event":"status"' "$T/$tag.out")" -ge 2 ] && break
        kill -0 $NPID 2>/dev/null || break; sleep 0.1; i=$((i+1)); done
    exec 9>&-                             # close stdin: node exits
    j=0; while kill -0 $NPID 2>/dev/null && [ $j -lt 100 ]; do sleep 0.1; j=$((j+1)); done
    kill $NPID 2>/dev/null; NPID=
}

echo "-- dane-01/02: --dane-api mints no CA, ready line has no ca --"
run_node a 20 PEPENET_DNS_LISTEN=0
READY=$(grep -m1 '"event":"ready"' "$T/a.out")
[ -n "$READY" ]; check $? "ready line emitted"
echo "$READY" | grep -q '"dane_api":1'; check $? "ready line says dane_api 1"
echo "$READY" | grep -q '"ca"'; [ $? != 0 ]; check $? "ready line has no \"ca\" field"
echo "$READY" | grep -q 'pepenet-root'; [ $? != 0 ]; check $? "ready line names no root cert"
N=$(find "$T/a" -name 'pepenet-root-*' | wc -l)
[ "$N" = 0 ]; check $? "--dane-api run created no pepenet-root-* file (found $N)"
grep -q '"event":"status"' "$T/a.out"; check $? "status event emitted"
grep '"event":"status"' "$T/a.out" | tail -1 | grep -q '"listen":"off"'; check $? "listen=0 reports \"listen\":\"off\""

echo "-- dane-03: a failed chain-port bind is visible in the status event --"
PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("0.0.0.0",0));print(s.getsockname()[1])')
python3 -c 'import socket,time,sys
s=socket.socket();s.bind(("0.0.0.0",int(sys.argv[1])));s.listen(1);time.sleep(120)' "$PORT" &
HOLD=$!; sleep 0.5
run_node b 20 PEPENET_DNS_LISTEN=$PORT
ST=$(grep '"event":"status"' "$T/b.out" | tail -1)
echo "     $ST"
echo "$ST" | grep -q '"listen":"bind_failed"'; check $? "status shows listen bind_failed"
echo "$ST" | grep -q "\"listen_port\":$PORT"; check $? "status carries the port ($PORT)"
echo "$ST" | grep -q '"listen_errno":98\|"listen_errno":48'; check $? "status carries errno EADDRINUSE"
echo "$ST" | grep -q '"listen_error":"Address already in use"'; check $? "status carries strerror text"
kill $HOLD 2>/dev/null; wait $HOLD 2>/dev/null; HOLD=

echo "-- dane-03: a good bind reports ok --"
PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("0.0.0.0",0));print(s.getsockname()[1])')
run_node c 20 PEPENET_DNS_LISTEN=$PORT
ST=$(grep '"event":"status"' "$T/c.out" | tail -1)
echo "     $ST"
echo "$ST" | grep -q "\"listen\":\"ok\",\"listen_port\":$PORT,\"listen_errno\":0"; check $? "status shows listen ok on $PORT"

echo "-- dane-05: exit within ~1s of stdin EOF and of SIGTERM, both chains --"
# The seed is a local peer that accepts and never speaks, so the sync pass is
# parked in a handshake read (8-15 s peer timeouts): exactly the state that
# used to keep the child alive after the browser quit.
SP=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')
python3 -c 'import socket,sys
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("127.0.0.1",int(sys.argv[1])));s.listen(16);c=[]
while 1: c.append(s.accept()[0])' "$SP" &
HOLD=$!; sleep 0.3
now_ms() { python3 -c 'import time;print(int(time.monotonic()*1000))'; }
for coin in pep doge; do for how in eof term; do
    tag=x_${coin}_$how; mkfifo "$T/$tag.in"
    PEPENET_DNS_LISTEN=0 "$NODE" --data "$T/$tag" --only $coin --ephemeral-ports --dane-api --stdio \
        --seeds 127.0.0.1:$SP < "$T/$tag.in" > "$T/$tag.out" 2> "$T/$tag.err" &
    NPID=$!; exec 9> "$T/$tag.in"
    i=0; while [ $i -lt 50 ] && ! grep -q 'connected\|unreachable\|handshake' "$T/$tag.err" 2>/dev/null; do
        grep -q '"event":"ready"' "$T/$tag.out" 2>/dev/null && [ $i -ge 25 ] && break
        sleep 0.1; i=$((i+1)); done
    sleep 0.5
    t0=$(now_ms)
    if [ $how = eof ]; then exec 9>&-; else kill -TERM $NPID; fi
    while kill -0 $NPID 2>/dev/null; do t=$(now_ms); [ $((t-t0)) -gt 5000 ] && break; sleep 0.02; done
    dt=$(( $(now_ms) - t0 ))
    exec 9>&-; kill -KILL $NPID 2>/dev/null; wait $NPID 2>/dev/null; NPID=
    [ $dt -le 1200 ]; check $? "$coin exits ${dt}ms after $how (limit 1200ms)"
done; done
kill $HOLD 2>/dev/null; wait $HOLD 2>/dev/null; HOLD=

echo "-- dane-05: --seeds is validated --"
"$NODE" --data "$T/v" --only doge --seeds 'bad seed;rm' >/dev/null 2>&1; [ $? = 2 ]; check $? "--seeds with bad characters is refused (exit 2)"

echo "-- dane-06: settings flags + richer status for about:preferences --"
# run6 <tag> <coin> <secs> [flags...]: plain run, stdin held open <secs>
run6() {
    tag=$1; coin=$2; secs=$3; shift 3
    mkfifo "$T/$tag.in"
    env -u PEPENET_DNS_LISTEN "$NODE" --data "$T/$tag" --only $coin --ephemeral-ports --dane-api --stdio "$@" \
        --seeds 127.0.0.1:9 < "$T/$tag.in" > "$T/$tag.out" 2> "$T/$tag.err" &
    NPID=$!; exec 9> "$T/$tag.in"
    sleep 2; printf '{"cmd":"status"}\n' >&9; sleep $((secs-2))
    exec 9>&-; wait $NPID 2>/dev/null; NPID=
}
for coin in pep doge; do
    [ $coin = pep ] && DEF=33874 || DEF=22556
    run6 d_$coin $coin 5
    ST=$(grep '"event":"status"' "$T/d_$coin.out" | tail -1)
    echo "     $ST"
    echo "$ST" | grep -q "\"listen\":\"ok\",\"listen_port\":$DEF"; check $? "$coin default listen ok on $DEF"
    for k in state sync_pct peers_in peers_out data_dir; do
        echo "$ST" | grep -q "\"$k\":"; check $? "$coin status has $k"; done
    echo "$ST" | grep -q "\"data_dir\":\"$T/d_$coin/$coin\""; check $? "$coin data_dir is the instance dir"
    N=$(grep -c '"event":"status"' "$T/d_$coin.out")
    [ "$N" -ge 2 ] && [ "$N" -le 7 ]; check $? "$coin status lines rate-limited over 5s ($N, want 2..7)"
done
run6 e pep 4 --no-listen
grep '"event":"status"' "$T/e.out" | tail -1 | grep -q '"listen":"off"'; check $? "--no-listen reports listen off"
LP=$(python3 -c 'import socket;s=socket.socket();s.bind(("0.0.0.0",0));print(s.getsockname()[1])')
run6 f doge 4 --listen-port $LP
grep '"event":"status"' "$T/f.out" | tail -1 | grep -q "\"listen\":\"ok\",\"listen_port\":$LP"; check $? "--listen-port $LP binds and reports ok"
"$NODE" --data "$T/g" --only pep --listen-port 0 >/dev/null 2>&1; [ $? = 2 ]; check $? "--listen-port 0 refused (use --no-listen)"

echo "-- dane-08: read-only /gd/name + /gd/owned on the PAC door --"
# seed one name row into the d_pep instance's fold db (created by the run above)
python3 -c 'import sqlite3,sys
c=sqlite3.connect(sys.argv[1]); c.execute("INSERT OR REPLACE INTO names(name,owner,owner_type,lease_expiry,st) VALUES(?,?,0,777,1)",("gdtest",bytes([0x22])*20)); c.commit()' "$T/d_pep/pep/pep.db"
check $? "seeded a name row into the fold db"
mkfifo "$T/n.in"
env -u PEPENET_DNS_LISTEN "$NODE" --data "$T/d_pep" --only pep --ephemeral-ports --dane-api --stdio --no-listen \
    --seeds 127.0.0.1:9 < "$T/n.in" > "$T/n.out" 2> "$T/n.err" &
NPID=$!; exec 9> "$T/n.in"
i=0; while [ $i -lt 50 ] && ! grep -q '"event":"ready"' "$T/n.out" 2>/dev/null; do sleep 0.1; i=$((i+1)); done
PAC=$(grep -m1 '"event":"ready"' "$T/n.out" | sed 's/.*"pac":\([0-9]*\).*/\1/')
gdq() { python3 -c 'import socket,sys
s=socket.create_connection(("127.0.0.1",int(sys.argv[1])),5)
s.sendall(("GET "+sys.argv[2]+" HTTP/1.1\r\nHost: x\r\n\r\n").encode()); b=b""
while 1:
    d=s.recv(4096)
    if not d: break
    b+=d
print(b.decode(errors="replace").replace("\r\n"," | "))' "$PAC" "$1"; }
R=$(gdq "/gd/name?n=gdtest.pepe"); echo "     $R"
echo "$R" | grep -q '200 OK.*"status":"ok","owner":"2222222222222222222222222222222222222222","state":1'; check $? "/gd/name resolves a fold-db row"
R=$(gdq "/gd/name?n=nosuchname"); echo "$R" | grep -q '"status":"unowned"'; check $? "/gd/name unknown → unowned"
R=$(gdq "/gd/name?n=Bad_Name"); echo "$R" | grep -q '400 Bad Request'; check $? "/gd/name bad charset → 400"
R=$(gdq "/gd/owned?h160=2222222222222222222222222222222222222222"); echo "     $R"
echo "$R" | grep -q '"names":\[{"name":"gdtest","lease_expiry":777,"state":1}\],"count":1,"truncated":false'; check $? "/gd/owned lists the row"
R=$(gdq "/gd/owned?h160=xyz"); echo "$R" | grep -q '400 Bad Request'; check $? "/gd/owned bad h160 → 400"

echo "-- dane-09: /gd/names listing --"
python3 -c 'import sqlite3,sys
c=sqlite3.connect(sys.argv[1])
c.executemany("INSERT OR REPLACE INTO names(name,owner,owner_type,lease_expiry,st) VALUES(?,?,0,?,1)",
  [("dn%03d"%i, bytes([0x33])*20 if i%2==0 else None, 1000+i) for i in range(150)]); c.commit()
q=" ".join(r[3] for r in c.execute("EXPLAIN QUERY PLAN SELECT name,owner,lease_expiry,st,price FROM names WHERE name >= ?1 AND name < ?2 ORDER BY name LIMIT ?3 OFFSET ?4",("dn","do",20,0)))
q2=" ".join(r[3] for r in c.execute("EXPLAIN QUERY PLAN SELECT COUNT(*) FROM names WHERE name >= ?1 AND name < ?2",("dn","do")))
print("     plan:",q,"/",q2)
sys.exit(0 if "USING" in q and "INDEX" in q and "name>? AND name<?" in q and "TEMP B-TREE" not in q and "name>? AND name<?" in q2 else 1)' "$T/d_pep/pep/pep.db"
check $? "seeded 150 names; prefix page + count use the name index (no scan/sort)"
R=$(gdq "/gd/names?prefix="); echo "     $(echo "$R" | cut -c1-200)…"
echo "$R" | grep -q '200 OK' && echo "$R" | grep -q '"total":151,"offset":0,"limit":20,"count":20'; check $? "/gd/names empty prefix → all 151, default limit 20"
R=$(gdq "/gd/names?prefix=dn&offset=100&limit=100")
echo "$R" | grep -q '"total":150,"offset":100,"limit":100,"count":50'; check $? "/gd/names offset 100 limit 100 → last 50"
R=$(gdq "/gd/names?prefix=DN01&limit=2")
echo "$R" | grep -q '"names":\[{"name":"dn010","owner_h160":"3333333333333333333333333333333333333333","lease_expiry":1010,"state":1,"price":0},{"name":"dn011","owner_h160":null,'; check $? "/gd/names ordered by name, owner_h160 hex/null"
for bq in "limit=101" "limit=0" "offset=-1" "offset=x" "prefix=a_b"; do
    R=$(gdq "/gd/names?$bq"); echo "$R" | grep -q '400 Bad Request'; check $? "/gd/names $bq → 400"; done
exec 9>&-; wait $NPID 2>/dev/null; NPID=

echo "-- idx-04: --snapshot + --snapshot-sha256 fail closed, node falls back to full sync --"
SD="$T/snap"; mkdir -p "$SD"
head -c 8192 /dev/urandom > "$SD/state.db"
printf 'pepenet-snapshot 1\ncoin pep\nheight 1\ntip %064d\nstate_digest %064d\nstate_ecmh %064d\n' 0 0 0 > "$SD/MANIFEST"
GOOD=$(sha256sum "$SD/state.db" | cut -c1-64)
BADPIN=$(printf x | sha256sum | cut -c1-64)
sn=0
for case in "mismatch:--snapshot $SD --snapshot-sha256 $BADPIN:sha256 mismatch" \
            "nopin:--snapshot $SD:no snapshot pin" \
            "badhex:--snapshot $SD --snapshot-sha256 xyz:malformed snapshot pin" \
            "pinok_badstate:--snapshot $SD --snapshot-sha256 $GOOD:REFUSED"; do
    sn=$((sn+1)); name=${case%%:*}; rest=${case#*:}; args=${rest%:*}; want=${rest##*:}
    NODE_ARGS="$args" run_node "sn$sn" 20 PEPENET_DNS_LISTEN=0
    grep -q "snapshot REFUSED: .*falling back to full sync" "$T/sn$sn.err"; check $? "$name: snapshot refused + logged"
    grep -q "$want" "$T/sn$sn.err"; check $? "$name: reason says '$want'"
    grep -q '"event":"status"' "$T/sn$sn.out"; check $? "$name: node still started (full-sync fallback)"
    if [ -f "$T/sn$sn/pep/pep.db" ] && cmp -s "$SD/state.db" "$T/sn$sn/pep/pep.db"; then r=1; else r=0; fi
    check $r "$name: the unverified state.db was never applied"
    [ ! -e "$T/sn$sn/pep/pep.db.snap-tmp" ]; check $? "$name: no temp file left behind"
done

echo
echo "gd_node_test: $ok ok, $bad failed"
[ $bad = 0 ]
