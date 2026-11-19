// dbcheck.h — idx-03 read-only db integrity/consistency check (see dbcheck.c).
#ifndef IDX_DBCHECK_H
#define IDX_DBCHECK_H
#include <stdint.h>
#include <stdio.h>
#include <sqlite3.h>
typedef struct { int errors, warnings; int64_t orphans, bad_names, height, proj_height; } IdxCheckReport;
// Returns the error count (0 = clean). serve_path may be NULL. out may be NULL.
int idx_db_check(const char *path, const char *serve_path, FILE *out, IdxCheckReport *r);
#endif
