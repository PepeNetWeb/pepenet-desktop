# fetchblk.py <host> <port> <magic_hex> <blockhash_internal_hex> — dial a chain
# peer, getdata the block, print its header fields (time, bits, prev hash).
import hashlib, socket, struct, sys, time

host, port = sys.argv[1], int(sys.argv[2])
MAGIC = bytes.fromhex(sys.argv[3])
want = bytes.fromhex(sys.argv[4])          # internal (little-endian) byte order

def sha256d(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def msg(cmd, payload=b""):
    return MAGIC + cmd.ljust(12, b"\0") + struct.pack("<I", len(payload)) + sha256d(payload)[:4] + payload

def version_payload():
    p = struct.pack("<i", 70015) + struct.pack("<Q", 0) + struct.pack("<q", int(time.time()))
    p += b"\0" * 52 + b"\x37" * 8 + b"\0" + struct.pack("<i", 0) + b"\0"
    return p

def read_msg(c):
    hdr = b""
    while len(hdr) < 24:
        ch = c.recv(24 - len(hdr))
        if not ch: raise EOFError
        hdr += ch
    cmd = hdr[4:16].rstrip(b"\0").decode()
    (plen,) = struct.unpack("<I", hdr[16:20])
    pl = b""
    while len(pl) < plen:
        ch = c.recv(plen - len(pl))
        if not ch: raise EOFError
        pl += ch
    return cmd, pl

c = socket.create_connection((host, port), timeout=15)
c.sendall(msg(b"version", version_payload()))
verack = False
while not verack:
    cmd, pl = read_msg(c)
    if cmd == "version": c.sendall(msg(b"verack"))
    elif cmd == "verack": verack = True
    elif cmd == "ping": c.sendall(msg(b"pong", pl))
c.sendall(msg(b"getdata", b"\x01" + struct.pack("<I", 2) + want))
deadline = time.time() + 30
while time.time() < deadline:
    cmd, pl = read_msg(c)
    if cmd == "ping": c.sendall(msg(b"pong", pl)); continue
    if cmd != "block": continue
    h = pl[:80]
    if sha256d(h) != want: continue
    ver, = struct.unpack("<I", h[0:4])
    tme, bits, nonce = struct.unpack("<III", h[68:80])
    print(f"hash    {want.hex()}")
    print(f"version 0x{ver:08x}  (auxpow={'yes' if ver & 0x100 else 'no'}, chainid=0x{ver >> 16:x})")
    print(f"prev    {h[4:36].hex()}")
    print(f"time    {tme}")
    print(f"bits    0x{bits:08x}")
    break
c.close()
