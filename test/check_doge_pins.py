#!/usr/bin/env python3
"""dane-07: assert the Dane tree's doge COINS profile equals namespace-indexer
ce68a5c (source tokens) and that the compiled object carries those values.
usage: check_doge_pins.py <ce68a5c sync.c> <dane sync.c> <compiled sync.o>"""
import re, struct, subprocess, sys, tempfile, os
def doge(path):
    s = open(path).read()
    i = s.index('{ "doge",'); j = s.index('// Pepecoin mainnet', i)
    body = re.sub(r'//[^\n]*', '', s[i:j])
    toks = re.findall(r'"[^"]*"|0x[0-9a-fA-F]+|\d+|[A-Z_0-9]+', body)
    return toks
ref, dane = doge(sys.argv[1]), doge(sys.argv[2])
ok = True
# Dane's Coin has one extra trailing field (onchain_magic 'D' 'N' = 0x44 0x4E)
if dane[:len(ref)] != ref or dane[len(ref):] != ['0x44', '0x4E']:
    print("FAIL source tokens differ\n ref ", ref, "\n dane", dane); ok = False
else: print("ok   doge profile tokens == ce68a5c (+ onchain_magic DN)")
with tempfile.TemporaryDirectory() as d:
    out = os.path.join(d, 'ro')
    subprocess.check_call(['objcopy', '-O', 'binary', '--only-section=.rodata*',
                           '--only-section=.data.rel.ro*', '--only-section=.data*', sys.argv[3], out])
    blob = open(out, 'rb').read() + open(sys.argv[3], 'rb').read()
h = bytes(int(t, 16) for t in ref[8:40])
need = {'activation 6429500': struct.pack('<q', 6429500), 'start 6418500': struct.pack('<q', 6418500),
        'checkpoint hash': h, 'seed.dogecoin.surf': b'seed.dogecoin.surf\0',
        'start_bits 0x19547b37': struct.pack('<I', 0x19547b37)}
for k, v in need.items():
    if v in blob: print("ok   compiled object has", k)
    else: print("FAIL compiled object lacks", k); ok = False
for k, v in {'old activation 6359500': struct.pack('<q', 6359500), 'old start 6348500': struct.pack('<q', 6348500)}.items():
    if v in blob: print("FAIL compiled object still has", k); ok = False
    else: print("ok   compiled object free of", k)
sys.exit(0 if ok else 1)
