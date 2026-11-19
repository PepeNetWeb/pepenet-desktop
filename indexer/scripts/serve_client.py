# serve_client.py <port> — exercise a pepenet serve node's NODE_NETWORK_LIMITED:
# getheaders from the checkpoint, then getdata the newest served block.
import hashlib, socket, struct, sys, time

MAGIC = bytes([0xC0, 0xA0, 0xF0, 0xE0])
PORT = int(sys.argv[1])
CKPT = bytes.fromhex("192fbc385151e3fd7a8089662ca6be87b17ddee72dd4cf58bf26a7c2fc152692")

def sha256d(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def msg(cmd, p=b""): return MAGIC + cmd.ljust(12, b"\0") + struct.pack("<I", len(p)) + sha256d(p)[:4] + p
def ver():
    p = struct.pack("<i", 70015) + struct.pack("<Q", 0) + struct.pack("<q", int(time.time()))
    p += b"\0"*52 + b"\x55"*8 + b"\0" + struct.pack("<i", 0) + b"\0"
    return p
def rd(c):
    h=b""
    while len(h)<24:
        x=c.recv(24-len(h))
        if not x: raise EOFError
        h+=x
    cmd=h[4:16].rstrip(b"\0").decode(); (n,)=struct.unpack("<I",h[16:20]); pl=b""
    while len(pl)<n:
        x=c.recv(n-len(pl))
        if not x: raise EOFError
        pl+=x
    return cmd,pl

c=socket.create_connection(("127.0.0.1",PORT),timeout=10)
c.sendall(msg(b"version",ver()))
peer_services=None
va=False
while not va:
    cmd,pl=rd(c)
    if cmd=="version":
        peer_services,=struct.unpack("<Q",pl[4:12])
        c.sendall(msg(b"verack"))
    elif cmd=="verack": va=True
    elif cmd=="ping": c.sendall(msg(b"pong",pl))
print(f"peer services = 0x{peer_services:x} (NODE_NETWORK_LIMITED={'yes' if peer_services & (1<<10) else 'no'})")

def get_headers(locator):
    gh = struct.pack("<I",70015) + b"\x01" + locator + b"\0"*32
    c.sendall(msg(b"getheaders",gh))
    deadline=time.time()+15
    while time.time()<deadline:
        cmd,pl=rd(c)
        if cmd=="ping": c.sendall(msg(b"pong",pl)); continue
        if cmd=="headers":
            o=0; n=pl[o]; o+=1
            if n==0xfd: n=pl[o]|pl[o+1]<<8; o+=2
            hs=[]
            for i in range(n):
                hs.append(pl[o:o+80]); o+=81   # 80-byte header + 0 tx-count
            return hs
    return []

# page getheaders from the checkpoint to the tip
all_h=[]; loc=CKPT; rounds=0
while True:
    page=get_headers(loc)
    if not page: break
    all_h+=page; loc=sha256d(page[-1]); rounds+=1
    if len(page)<2000: break
print(f"getheaders → {len(all_h)} headers over {rounds} pages")
prev=CKPT; ok=True
for hdr in all_h:
    if hdr[4:36]!=prev: ok=False; break
    prev=sha256d(hdr)
print(f"header chain links contiguously from checkpoint: {'YES' if ok else 'NO'}")
headers=all_h

# getdata the NEWEST served header's block (must be in the 288 window)
tiphash=sha256d(headers[-1])
inv=b"\x01"+struct.pack("<I",2)+tiphash
c.sendall(msg(b"getdata",inv))
deadline=time.time()+15
got=False
while time.time()<deadline:
    cmd,pl=rd(c)
    if cmd=="ping": c.sendall(msg(b"pong",pl)); continue
    if cmd=="block":
        got = sha256d(pl[:80])==tiphash
        print(f"getdata(block {tiphash[::-1].hex()[:16]}…) → {len(pl)} bytes, hash matches: {'YES' if got else 'NO'}")
        break
if not got: print("getdata → no block returned")
c.close()
