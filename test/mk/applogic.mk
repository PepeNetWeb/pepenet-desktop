# applogic.mk — the app-logic suites: on-chain op wire bytes, the zone hot key,
# the Discover directory scan, the Receive QR encoder, and the DNS record-editor
# validators. Each binary links ONLY the modules it exercises; nothing here
# opens a window, a socket, or the GUI toolkit.

TESTS += t_ops t_zonekey t_dirscan t_qr t_dnsrec

MESHSRC := $(ROOT)/mesh/src

# The header-collision dance the family repos all document: protocol-sm and
# libsecp both ship a "secp256k1.h". mesh/src/crypto.c needs protocol-sm's
# (the secp_* interface), so INC_MESH puts $(SM) AHEAD of the vendor include
# dir; secp_shim.c needs the vendored one, so INC_SHIM reverses them. The two
# orders cannot share a command line, hence objects rather than a one-shot link
# — and the objects are stamped by applogic_mesh.o so both suites share them.
INC_MESH := -I$(SRC) -I$(MESHINC) -I$(SM) -I$(DNSSRC) -I$(IDX) -I$(SECPDIR)/include
INC_SHIM := -I$(SECPDIR)/include -I$(SM)

applogic_mesh.o: $(MESHSRC)/crypto.c $(MESHSRC)/state.c $(MESHSRC)/wire.c $(SHIM)
	$(CC) $(CFLAGS) $(INC_MESH) -c $(MESHSRC)/crypto.c -o applogic_mesh_crypto.o
	$(CC) $(CFLAGS) $(INC_MESH) -c $(MESHSRC)/state.c  -o applogic_mesh_state.o
	$(CC) $(CFLAGS) $(INC_MESH) -c $(MESHSRC)/wire.c   -o applogic_mesh_wire.o
	$(CC) $(CFLAGS) $(INC_SHIM) -c $(SHIM)             -o applogic_shim.o
	$(CC) $(CFLAGS) $(INC_MESH) -c $(SM)/sha256.c      -o applogic_sha256.o
	$(CC) $(CFLAGS) $(INC_MESH) -c $(SM)/ripemd160.c   -o applogic_ripemd160.o
	@touch $@

MESHOBJ := applogic_mesh_crypto.o applogic_mesh_state.o applogic_mesh_wire.o \
           applogic_shim.o applogic_sha256.o applogic_ripemd160.o

# ── the consensus wire bytes (src/ops.c queue + the §2 action codec) ─────────
t_ops: t_ops.c $(SRC)/ops.c $(SRC)/ui/strings.c $(SM)/decode.c $(SM)/state.c
	$(CC) $(CFLAGS) $(INC) -o $@ $^ $(LDFLAGS) $(LDLIBS)

# ── the zone hot key + its delegation cert cache ─────────────────────────────
t_zonekey: t_zonekey.c $(SRC)/zonekey.c applogic_mesh.o
	$(CC) $(CFLAGS) $(INC_MESH) -o $@ t_zonekey.c $(SRC)/zonekey.c $(MESHOBJ) \
	      $(LDFLAGS) $(SECPLIB) -lsqlite3

# ── the Discover directory scan ──────────────────────────────────────────────
# (dirscan.c is #included by the test — a prerequisite, not a compile input —
#  so the suite can drive its static rebuild() instead of racing the timer)
t_dirscan: t_dirscan.c $(SRC)/dirscan.c $(DNSSRC)/dns_state.c $(DNSSRC)/zone.c $(DNSSRC)/dns_wire.c applogic_mesh.o
	$(CC) $(CFLAGS) $(INC_MESH) -o $@ t_dirscan.c \
	      $(DNSSRC)/dns_state.c $(DNSSRC)/zone.c $(DNSSRC)/dns_wire.c $(MESHOBJ) \
	      $(LDFLAGS) $(SECPLIB) -lsqlite3

# ── the Receive card's QR encoder + the Discover favicon decoder ─────────────
# (favicon.c is #included by the test — its decoders are static, and its one
#  network call is stubbed; -I$(TLSSRC) is only for fetch.h's prototype)
t_qr: t_qr.c $(SRC)/qr.c $(SRC)/favicon.c
	$(CC) $(CFLAGS) $(INC) -I$(TLSSRC) -o $@ t_qr.c $(SRC)/qr.c $(LDFLAGS)

# ── the DNS record-editor validators (mirrored helpers + the REAL rdata parser)
t_dnsrec: t_dnsrec.c $(DNSSRC)/zone.c $(DNSSRC)/dns_wire.c
	$(CC) $(CFLAGS) $(INC) -o $@ $^ $(LDFLAGS)
