// applog.h — a 10 MB circular flat file next to the db. Last 10 MB of
// stderr (and explicit applog_printf) survive a vanish with no crash report.
#ifndef PEPENET_APPLOG_H
#define PEPENET_APPLOG_H

#include <stddef.h>
#include <stdio.h>

#define APPLOG_CAP (10u * 1024u * 1024u)

// Open (create/reuse) the circular file at path. Idempotent. Returns 1 on ok.
int  applog_open(const char *path);
void applog_close(void);

// Capture stderr into the ring (and still echo to the original stderr fd
// if that was a tty / already-open stream). Call once after applog_open.
void applog_hook_stderr(void);

void applog_write(const void *p, size_t n);
void applog_printf(const char *fmt, ...)
#ifdef __GNUC__
    __attribute__((format(printf, 1, 2)))
#endif
    ;

// Linearize the ring onto out (oldest → newest). --log-dump uses this.
void applog_dump(FILE *out);

#endif
