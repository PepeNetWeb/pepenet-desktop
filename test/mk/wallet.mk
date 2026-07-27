# wallet.mk — the money suites: the recovery phrase (t_bip39), BIP32/BIP44 key
# derivation (t_hdwallet), coin selection + change conservation (t_wallet) and
# the fee quote (t_fee). Everything here is hermetic: no window server, no
# socket, no OS keystore. t_wallet builds a throwaway SQLite projection under
# /tmp and drives the REAL swl_run with dry_run=1, so a full tx is funded,
# signed and self-checked without a single byte leaving the machine.
#
# Each target links only what it needs:
#   t_bip39     bip39 + wordlist + the engine's sha256   (+ libcrypto: PBKDF2)
#   t_hdwallet  hdwallet                                 (+ libsecp, libcrypto)
#   t_fee       fee                                      (nothing else)
#   t_wallet    wallet.c and its whole dependency cone — the indexer's
#               projection/attribution/base58 and the §3 protocol impl

WLT_SSL_INC := -I$(OPENSSL)/include
WLT_SSL_LIB := -L$(OPENSSL)/lib -lcrypto

# wallet.c's cone. secp256k1.c in the protocol impl is the stub the vendored
# libsecp replaces (secp_shim.c) — linking both is a duplicate-symbol error;
# main.c is the protocol CLI's entry point.
WLT_IDX := $(IDX)/base58.c $(IDX)/chain.c $(IDX)/db.c $(IDX)/attrib.c $(IDX)/adapter.c
WLT_SM  := $(filter-out $(SM)/main.c $(SM)/secp256k1.c,$(wildcard $(SM)/*.c))

TESTS += t_bip39 t_hdwallet t_wallet t_fee

t_bip39: t_bip39.c $(SRC)/bip39.c $(SRC)/bip39_wordlist.c $(SM)/sha256.c
	$(CC) $(CFLAGS) $(INC) $(WLT_SSL_INC) -o $@ $^ $(LDFLAGS) $(WLT_SSL_LIB)

t_hdwallet: t_hdwallet.c $(SRC)/hdwallet.c $(SECPLIB)
	$(CC) $(CFLAGS) $(INC) $(WLT_SSL_INC) -o $@ t_hdwallet.c $(SRC)/hdwallet.c \
	  $(LDFLAGS) $(SECPLIB) $(WLT_SSL_LIB)

t_fee: t_fee.c $(SRC)/fee.c
	$(CC) $(CFLAGS) $(INC) -o $@ $^ $(LDFLAGS)

t_wallet: t_wallet.c $(SRC)/bip39.c $(SRC)/bip39_wordlist.c $(SRC)/hdwallet.c \
          $(WLT_IDX) $(WLT_SM) $(SHIM) $(SECPLIB)
	$(CC) $(CFLAGS) $(INC) $(WLT_SSL_INC) -o $@ \
	  t_wallet.c $(SRC)/bip39.c $(SRC)/bip39_wordlist.c $(SRC)/hdwallet.c \
	  $(WLT_IDX) $(WLT_SM) $(SHIM) \
	  $(LDFLAGS) $(SECPLIB) -lsqlite3 $(WLT_SSL_LIB)
