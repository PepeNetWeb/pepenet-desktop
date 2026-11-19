#!/usr/bin/env python3
# TCP DNS slow-loris vs UDP liveness (run under `unshare -rn`; brings lo up).
# Starts `dnsd --no-sync` on a throwaway loopback port with empty throwaway
# stores, then holds TCP connections open in every hostile shape — slow
# (a query every 2 s), idle (connect, send nothing), trickling (one byte every
# 0.5 s), a reader that never reads its answers, and a flood from many source
# IPs — while UDP queries are fired every 0.2 s. UDP must keep answering
# promptly, an honest TCP query from a fresh source must still be answered,
# the per-IP and total caps and the 10 s lifetime must hold.
# Pre-fix dnsd served TCP inline on the resolver thread: UDP starved.
import os, socket, struct, subprocess, sys, tempfile, threading, time
DNSD = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), '..', 'dnsd')
SUFFIX = sys.argv[2] if len(sys.argv) > 2 else 'pepe'
KILL = 60
subprocess.call(['ip', 'link', 'set', 'lo', 'up'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
fails = 0
def ck(c, n):
    global fails
    print(('ok   ' if c else 'FAIL ') + n, flush=True); fails += 0 if c else 1
def q(qid, name='x.' + SUFFIX):
    nm = b''.join(bytes([len(x)]) + x for x in name.encode().split(b'.')) + b'\0'
    return struct.pack('>HHHHHH', qid, 0x0100, 1, 0, 0, 0) + nm + struct.pack('>HH', 1, 1)
def free_port():
    while True:
        t = socket.socket(); t.bind(('127.0.0.1', 0)); p = t.getsockname()[1]; t.close()
        if p not in (15353, 8443, 8444, 8445): return p
d = tempfile.mkdtemp(prefix='dns-loris-')
port = free_port()
chain_port = free_port()   # throwaway overlay listener too (never the coin default)
p = subprocess.Popen([DNSD, '--db', os.path.join(d, 'idx.db'), '--store', os.path.join(d, 'zones.db'),
                      '--no-sync', '--dns-addr', '127.0.0.1', '--dns-port', str(port),
                      '--listen', str(chain_port)],
                     stdout=subprocess.DEVNULL, stderr=open(os.path.join(d, 'dnsd.err'), 'w'))
killer = threading.Timer(KILL, p.kill); killer.daemon = True; killer.start()
def udp_rtt(timeout=1.0, qid=7):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
    t = time.time(); s.sendto(q(qid), ('127.0.0.1', port))
    try:
        r, _ = s.recvfrom(4096); return time.time() - t if r[:2] == struct.pack('>H', qid) else None
    except socket.timeout: return None
    finally: s.close()
def tcp(src):
    c = socket.socket(); c.bind((src, 0)); c.settimeout(2); c.connect(('127.0.0.1', port)); return c
def tcp_query(src, qid=11):
    c = tcp(src); m = q(qid); c.sendall(struct.pack('>H', len(m)) + m)
    try:
        h = c.recv(2); n = struct.unpack('>H', h)[0]; b = b''
        while len(b) < n:
            x = c.recv(n - len(b))
            if not x: break
            b += x
        return len(b) == n and b[:2] == struct.pack('>H', qid)
    except (OSError, struct.error): return False
    finally: c.close()
def closed_by_peer(c, within):
    c.settimeout(0.25); t0 = time.time()
    while time.time() - t0 < within:
        try:
            x = c.recv(65536)
            if x == b'': return time.time() - t0
        except socket.timeout: continue
        except OSError: return time.time() - t0
    return None
try:
    for _ in range(100):
        if udp_rtt(0.2) is not None: break
        time.sleep(0.1)
    base = udp_rtt()
    ck(base is not None, 'udp answers before the attack (%.4f s)' % (base or -1))
    stop = threading.Event(); held = []; lock = threading.Lock()
    def slow(src):                                    # one query every 2 s, never closes
        try:
            c = tcp(src); held.append(c)
            while not stop.is_set():
                m = q(9); c.sendall(struct.pack('>H', len(m)) + m); time.sleep(2)
        except OSError: pass
    def trickle(src):                                 # a query, one byte per 0.5 s
        try:
            c = tcp(src); held.append(c); m = q(10); m = struct.pack('>H', len(m)) + m
            i = 0
            while not stop.is_set():
                c.sendall(m[i % len(m):i % len(m) + 1]); i += 1; time.sleep(0.5)
        except OSError: pass
    def idle(src):
        try: held.append(tcp(src))
        except OSError: pass
    def noread(src):                                  # pipelines queries, never reads
        try:
            c = socket.socket(); c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)
            c.bind((src, 0)); c.settimeout(2); c.connect(('127.0.0.1', port)); held.append(c)
            m = q(12); m = struct.pack('>H', len(m)) + m
            while not stop.is_set(): c.sendall(m * 50); time.sleep(0.05)
        except OSError: pass
    ths = [threading.Thread(target=f, args=(a,), daemon=True) for f, a in
           [(slow, '127.0.0.2'), (slow, '127.0.0.2'), (trickle, '127.0.0.3'), (trickle, '127.0.0.3'),
            (idle, '127.0.0.4'), (noread, '127.0.0.5')] +
           [(idle, '127.0.1.%d' % i) for i in range(1, 25)]]     # flood: 24 more sources
    for t in ths: t.start()
    time.sleep(0.5)
    # per-IP cap: a third connection from the slow client's source is closed at once
    try:
        extra = tcp('127.0.0.2'); dt = closed_by_peer(extra, 2.0); extra.close()
    except OSError: dt = None                        # not even accepted: the server is wedged
    ck(dt is not None, 'third conn from one IPv4 source is refused (per-IP cap 2)')
    rtts = []; lost = 0; t0 = time.time()
    while time.time() - t0 < 12:
        r = udp_rtt(1.0, qid=100 + len(rtts) + lost)
        if r is None: lost += 1
        else: rtts.append(r)
        time.sleep(0.2)
    n = len(rtts) + lost
    worst = max(rtts) if rtts else -1
    print('     udp during attack: %d/%d answered, worst rtt %.3f s' % (len(rtts), n, worst), flush=True)
    ck(n > 0 and lost == 0, 'every UDP query answered while TCP clients misbehave (%d lost)' % lost)
    ck(rtts and worst < 0.25, 'UDP answers stay prompt (worst %.3f s < 0.25 s)' % worst)
    stop.set()
    time.sleep(0.5)
    # lifetime: a fresh trickler is cut by the 10 s absolute deadline
    m = q(13); m = struct.pack('>H', len(m)) + m
    t1 = time.time(); cut = None; i = 0
    try: c = tcp('127.0.0.9'); c.settimeout(0.5)
    except OSError: c = None
    while c is not None and time.time() - t1 < 14 and cut is None:
        try:
            c.sendall(m[i % len(m):i % len(m) + 1]); i += 1
            x = c.recv(65536)
            if x == b'': cut = time.time() - t1
        except socket.timeout: pass
        except OSError: cut = time.time() - t1
    if c is not None: c.close()
    print('     trickler cut after %s' % ('%.1f s' % cut if cut else 'NEVER'), flush=True)
    ck(cut is not None and cut <= 11.5, 'a trickling TCP client is closed by the 10 s lifetime')
    try: hq = tcp_query('127.0.0.200')
    except OSError: hq = False
    ck(hq, 'an honest TCP query from a fresh source is answered')
    ck(udp_rtt() is not None, 'udp still answers after the attack')
finally:
    for c in list(held) if 'held' in dir() else []:
        try: c.close()
        except OSError: pass
    p.terminate()
    try: p.wait(5)
    except subprocess.TimeoutExpired: p.kill()
    killer.cancel()
print('tcp_loris_test: %s' % ('ALL PASSED' if not fails else '%d FAILED' % fails))
sys.exit(1 if fails else 0)
