# update.mk — the notify-only update check (t_update). Hermetic: the platform
# HTTP seam is stubbed in the test, so no socket is opened; t_update.c
# #includes update.c to reach its static parse/compare/check internals and
# pins its own PEPENET_VERSION (independent of CMake's).

TESTS += t_update

t_update: t_update.c $(SRC)/update.c $(SRC)/update.h
	$(CC) $(CFLAGS) $(INC) -o $@ t_update.c $(LDFLAGS)
