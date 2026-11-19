#!/usr/bin/env python3
# Sync-pass slow-loris bounds (run under `unshare -rn`).
# `indexerd sync regtest <db> 127.0.0.1:<port>` is pointed at ONE fake peer that
# completes the version/verack handshake and then misbehaves without ever going
# silent: it keeps sending ping/addr/inv (or drips a frame a byte at a time) but
# never the blocks or headers the node asked for. Every net_recv wait used to
# restart its timeout on each message (and read_n on each byte), so these
# passes never ended. With the per-batch / per-weigh / per-round / handshake
# deadlines the pass must end, drop the peer, and keep what already folded.
#
# Needs a binary built with SHORT deadlines (make check builds
# ./indexerd-stalltest): batch 6 s, weigh 4 s, getblocks round 2 s, handshake 3 s.
# An honest peer (blocks with interleaved ping/addr) must still sync fully.
# Last: `indexerd serve` dialing a peer that trickles its version frame must
# not wedge the serve loop (PepeNet multiplexes it; kept as coverage).
import hashlib, os, socket, struct, subprocess, sys, tempfile, threading, time
IDX = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), '..', 'indexerd-stalltest')
MAGIC = bytes([0xFA, 0xBF, 0xB5, 0xDA])                 # regtest
START = bytes.fromhex('a573e91c1772076c0d40f70e4408c83a31705f296ae6e7629d4adcb5a360213d')  # internal order
LIMIT = 20.0         # a bounded attack scenario must end well inside this
KILL = 45.0          # harness backstop: never let a hung pass hold the box
subprocess.call(['ip', 'link', 'set', 'lo', 'up'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
fails = 0
def ck(c, n):
    global fails
    print(('ok   ' if c else 'FAIL ') + n, flush=True); fails += 0 if c else 1
def d2(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def msg(cmd, p=b''):
    return MAGIC + cmd.encode().ljust(12, b'\0') + struct.pack('<I', len(p)) + d2(p)[:4] + p
def version(h):
    return (struct.pack('<iQq', 70015, 1, int(time.time())) + bytes(52) +
            os.urandom(8) + b'\x08/t:0.1/' + struct.pack('<i', h) + b'\x01')
def recv_cmd(c):
    h = b''
    while len(h) < 24:
        x = c.recv(24 - len(h))
        if not x: raise EOFError
        h += x
    n = struct.unpack('<I', h[16:20])[0]; p = b''
    while len(p) < n:
        x = c.recv(n - len(p))
        if not x: raise EOFError
        p += x
    return h[4:16].rstrip(b'\0').decode(), p
T0 = int(time.time()) - 100000
def block(prev, i):
    tx = (struct.pack('<i', 1) + b'\x01' + bytes(32) + b'\xff\xff\xff\xff' +
          b'\x05' + b'\x04' + struct.pack('<I', i) +
          b'\xff\xff\xff\xff' + b'\x01' + struct.pack('<q', 0) + b'\x01\x51' + struct.pack('<I', 0))
    merkle = d2(tx)
    hdr = struct.pack('<i', 1) + prev + merkle + struct.pack('<III', T0 + 60 * i, 0x207fffff, i)
    return hdr + b'\x01' + tx, d2(hdr)
B1, H1 = block(START, 1)
B2, H2 = block(H1, 2)
B3, H3 = block(H2, 3)
X2, HX = block(H1, 1002)                                  # fork off B1 (sibling of B2)
def inv(*hs): return bytes([len(hs)]) + b''.join(struct.pack('<I', 2) + h for h in hs)
ADDR = b'\x01' + struct.pack('<I', int(time.time())) + struct.pack('<Q', 1) + bytes(10) + b'\xff\xff' + bytes([10, 9, 9, 9]) + struct.pack('>H', 18444)
def chatter(c, stop, inv_too=True):
    """slow-loris: never silent, never useful (a tx inv would count as an idle
    round on the getblocks wait, so that scenario sends ping/addr only)"""
    k = 0
    while not stop.is_set():
        k += 1
        if not inv_too and k % 3 == 0: k += 1
        c.sendall(msg('ping', struct.pack('<Q', k)) if k % 3 == 1 else
                  msg('addr', ADDR) if k % 3 == 2 else msg('inv', b'\x01' + struct.pack('<I', 1) + os.urandom(32)))
        time.sleep(0.5)
def drip(c, stop, cmd, n):
    """slow-loris inside ONE frame: header announces n bytes, payload trickles"""
    c.sendall(MAGIC + cmd.encode().ljust(12, b'\0') + struct.pack('<I', n) + bytes(4))
    while not stop.is_set():
        c.sendall(b'\x00'); time.sleep(0.5)

def peer(lst, mode, stop, log):
    try:
        c, _ = lst.accept()
    except OSError:
        return
    c.settimeout(1.0)
    try:
        if mode == 'shake-drip':
            drip(c, stop, 'version', 4000); return
        c.sendall(msg('version', version(3)) + msg('verack'))
        rounds = 0
        while not stop.is_set():
            try: cmd, p = recv_cmd(c)
            except socket.timeout: continue
            log.append(cmd)
            if cmd == 'ping': c.sendall(msg('pong', p)); continue
            if cmd == 'getblocks':
                rounds += 1
                if mode == 'getblocks-chatter': chatter(c, stop, inv_too=False); return
                if rounds == 1:
                    c.sendall(msg('inv', inv(H1, H2) if mode != 'honest' else inv(H1, H2, H3)))
                elif rounds == 2 and mode in ('getdata-chatter', 'getdata-drip'):
                    c.sendall(msg('inv', inv(os.urandom(32))))
                elif rounds == 2 and mode == 'weigh-chatter':
                    c.sendall(msg('inv', inv(HX)))
                # else: at tip → silence, like Core
                continue
            if cmd == 'getdata':
                n = p[0]; hs = [p[1 + 36 * i + 4: 1 + 36 * i + 36] for i in range(n)]
                if mode in ('getdata-chatter', 'getdata-drip') and rounds == 2:
                    if mode == 'getdata-chatter': chatter(c, stop)
                    else: drip(c, stop, 'block', 4000)
                    return
                if mode == 'weigh-chatter' and rounds == 2:
                    c.sendall(msg('block', X2)); continue
                for h in hs:
                    b = {H1: B1, H2: B2, H3: B3}.get(h)
                    if mode == 'honest':          # honest but chatty and a bit slow
                        c.sendall(msg('ping', os.urandom(8)) + msg('addr', ADDR)); time.sleep(0.4)
                    if b: c.sendall(msg('block', b))
                continue
            if cmd == 'getheaders' and mode == 'weigh-chatter':
                chatter(c, stop); return
    except (OSError, EOFError):
        pass
    finally:
        try: c.close()
        except OSError: pass

def run(name, mode, want_rc, want_height, want_log, bounded=True):
    d = tempfile.mkdtemp(); db = os.path.join(d, 'db1')
    lst = socket.socket(); lst.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lst.bind(('127.0.0.1', 0)); lst.listen(4)
    port = lst.getsockname()[1]
    stop = threading.Event(); log = []
    th = threading.Thread(target=peer, args=(lst, mode, stop, log), daemon=True); th.start()
    t0 = time.time()
    p = subprocess.Popen([IDX, 'sync', 'regtest', db, '127.0.0.1:%d' % port],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        out, err = p.communicate(timeout=KILL); rc = p.returncode
    except subprocess.TimeoutExpired:
        p.kill(); out, err = p.communicate(); rc = None
    dt = time.time() - t0
    stop.set(); lst.close(); th.join(3)
    hs = [int(l.split()[1]) for l in err.splitlines() if l.strip().startswith('height ')]
    h = max(hs) if hs else 0
    print('     %-18s rc=%s elapsed=%.1fs height=%d peer-saw=%s' % (mode, rc, dt, h, ','.join(sorted(set(log)))), flush=True)
    if rc is None:
        ck(False, '%s: pass ended (still running after %.0fs harness kill)' % (name, KILL)); return
    if bounded: ck(dt < LIMIT, '%s: ended in %.1fs (< %.0fs)' % (name, dt, LIMIT))
    ck(rc == want_rc, '%s: rc %s (want %s)' % (name, rc, want_rc))
    ck(h == want_height, '%s: folded height %d kept (want %d)' % (name, h, want_height))
    if want_log: ck(want_log in err, '%s: log says %r' % (name, want_log))
    if want_log == 'stalled':           # dropped AND demoted: the ladder rotates away from it
        import sqlite3
        m = sqlite3.connect(db); r = m.execute("SELECT last_good FROM peers WHERE addr=?", ('127.0.0.1:%d' % port,)).fetchone(); m.close()
        ck(r is not None and r[0] == 0, '%s: peer demoted (last_good %s)' % (name, r and r[0]))
    if os.environ.get('STALL_VERBOSE'): sys.stderr.write(err)

run('honest chatty peer syncs fully', 'honest', 0, 3, 'caught up at height 3', bounded=False)
run('getdata answered with ping/addr/inv only', 'getdata-chatter', 1, 2, 'stalled')
run('getdata answered with a 1-byte/0.5s block drip', 'getdata-drip', 1, 2, 'stalled')
run('getheaders (branch weigh) answered with chatter', 'weigh-chatter', 1, 2, 'stalled')
run('getblocks answered with chatter, never inv', 'getblocks-chatter', 0, 0, 'sync idle')
run('handshake: version frame dripped a byte at a time', 'shake-drip', 1, 0, 'handshake failed')
# serve outbound handshake (multiplexed on PepeNet since 04b49cf): a configured
# peer that accepts and trickles its version frame must not wedge the serve
# loop — an inbound peer must still get its version answered.
def run_serve_dial():
    import sqlite3
    DM = bytes([0xC0, 0xA0, 0xF0, 0xE0])        # pep
    def dmsg(cmd, pl=b''):
        return DM + cmd.encode().ljust(12, b'\0') + struct.pack('<I', len(pl)) + d2(pl)[:4] + pl
    d = tempfile.mkdtemp(); db = os.path.join(d, 'db1')
    s = sqlite3.connect(os.path.join(d, 'serve-pep.db'))
    s.executescript("CREATE TABLE headers(height INTEGER PRIMARY KEY, hash BLOB, hdr BLOB);"
                    "CREATE INDEX headers_hash ON headers(hash);"); s.commit(); s.close()
    lst = socket.socket(); lst.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lst.bind(('127.0.0.1', 0)); lst.listen(4); lst.settimeout(15)
    fport = lst.getsockname()[1]
    probe = socket.socket(); probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]; probe.close()
    stop = threading.Event(); dialed = []
    def dripper():
        try: c, _ = lst.accept()
        except OSError: return
        dialed.append(time.time())
        try:
            c.sendall(DM + b'version'.ljust(12, b'\0') + struct.pack('<I', 4000) + bytes(4))
            while not stop.is_set(): c.sendall(b'\x00'); time.sleep(0.5)
        except OSError: pass
        finally: c.close()
    th = threading.Thread(target=dripper, daemon=True); th.start()
    p = subprocess.Popen([IDX, 'serve', 'pep', db, str(port), '127.0.0.1:%d' % fport],
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    answered = None
    try:
        t0 = time.time()
        while not dialed and time.time() - t0 < 15: time.sleep(0.1)
        ck(bool(dialed), 'serve_dial: the configured peer was dialed')
        time.sleep(0.5)                          # serve thread is now inside serve_dial
        t1 = time.time()
        try:
            c = socket.create_connection(('127.0.0.1', port), 2); c.settimeout(1)
            c.sendall(dmsg('version', version(1)))
            while time.time() - t1 < 12 and answered is None:
                try:
                    cmd, _ = recv_cmd(c)
                    if cmd == 'version': answered = time.time() - t1
                except socket.timeout: continue
            c.close()
        except (OSError, EOFError): pass
    finally:
        stop.set(); p.terminate()
        try: p.communicate(timeout=5)
        except subprocess.TimeoutExpired: p.kill(); p.communicate()
        lst.close()
    print('     serve-dial-drip    inbound version answered after %s' % ('%.1fs' % answered if answered is not None else 'NEVER (12 s)'), flush=True)
    ck(answered is not None and answered < 8, 'serve_dial: trickled outbound handshake does not wedge the serve loop')
run_serve_dial()
print('test_sync_stall: %s' % ('ALL PASSED' if not fails else '%d FAILED' % fails))
sys.exit(1 if fails else 0)
