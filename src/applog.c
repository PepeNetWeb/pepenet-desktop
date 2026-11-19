// applog.c — see applog.h. One 10 MB file, header + payload, wrap on full.
#include "applog.h"

#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

#define HDR  64
#define PAY  (APPLOG_CAP - HDR)
#define MAGIC "PNLOG01"

typedef struct {
    char     magic[8];
    uint64_t pos;          // next write offset into payload
    uint64_t wrapped;      // 0 until the first wrap
    uint8_t  pad[HDR - 24];
} Hdr;
_Static_assert(sizeof(Hdr) == HDR, "Hdr must be 64 bytes");

static struct {
    pthread_mutex_t mu;
    FILE *f;
    int   fd;
    Hdr   h;
    int   hooked;
    int   echo;            // original stderr fd, or -1
    pthread_t th;
} g = { .mu = PTHREAD_MUTEX_INITIALIZER, .fd = -1, .echo = -1 };

// 1 = header was valid. 0 = repaired in memory; caller must hdr_store.
static int hdr_load(void) {
    if (fseeko(g.f, 0, SEEK_SET) != 0) goto reset;
    if (fread(&g.h, 1, sizeof g.h, g.f) != sizeof g.h) goto reset;
    if (memcmp(g.h.magic, MAGIC, 8) != 0 || g.h.pos >= PAY) goto reset;
    return 1;
reset:
    memset(&g.h, 0, sizeof g.h);
    memcpy(g.h.magic, MAGIC, 8);
    return 0;
}
static void hdr_store(void) {
    if (fseeko(g.f, 0, SEEK_SET) != 0) return;
    fwrite(&g.h, 1, sizeof g.h, g.f);
}

static void put_unlocked(const uint8_t *p, size_t n) {
    if (!g.f || n == 0) return;
    if (n > PAY) { p += n - PAY; n = PAY; }     // keep the tail
    size_t room = PAY - (size_t)g.h.pos;
    if (fseeko(g.f, (off_t)(HDR + g.h.pos), SEEK_SET) != 0) return;
    if (n <= room) {
        fwrite(p, 1, n, g.f);
        g.h.pos += n;
        if (g.h.pos == PAY) { g.h.pos = 0; g.h.wrapped = 1; }
    } else {
        fwrite(p, 1, room, g.f);
        if (fseeko(g.f, HDR, SEEK_SET) != 0) return;
        fwrite(p + room, 1, n - room, g.f);
        g.h.pos = n - room;
        g.h.wrapped = 1;
    }
    hdr_store();
    fflush(g.f);
}

int applog_open(const char *path) {
    if (g.f) return 1;
    FILE *f = fopen(path, "r+b");
    if (!f) f = fopen(path, "w+b");
    if (!f) return 0;
    if (fseeko(f, 0, SEEK_END) != 0) { fclose(f); return 0; }
    off_t sz = ftello(f);
    if (sz != (off_t)APPLOG_CAP) {
#ifdef _WIN32
        if (_chsize_s(_fileno(f), (int64_t)APPLOG_CAP) != 0) { fclose(f); return 0; }
#else
        if (ftruncate(fileno(f), (off_t)APPLOG_CAP) != 0) { fclose(f); return 0; }
#endif
        if (sz <= 0) {
            // first create: zero the payload so a dump of an unwrapped file
            // doesn't spray uninitialized bytes
            char z[4096] = {0};
            fseeko(f, 0, SEEK_SET);
            for (size_t left = APPLOG_CAP; left; ) {
                size_t n = left < sizeof z ? left : sizeof z;
                if (fwrite(z, 1, n, f) != n) { fclose(f); return 0; }
                left -= n;
            }
            fflush(f);
        }
    }
    g.f = f;
#ifdef _WIN32
    g.fd = _fileno(f);
#else
    g.fd = fileno(f);
#endif
    if (!hdr_load()) { hdr_store(); fflush(g.f); }
    return 1;
}

void applog_close(void) {
    pthread_mutex_lock(&g.mu);
    if (g.f) { fflush(g.f); fclose(g.f); g.f = NULL; g.fd = -1; }
    pthread_mutex_unlock(&g.mu);
}

void applog_write(const void *p, size_t n) {
    if (!p || n == 0) return;
    pthread_mutex_lock(&g.mu);
    put_unlocked(p, n);
    pthread_mutex_unlock(&g.mu);
}

void applog_printf(const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (n >= (int)sizeof buf) n = (int)sizeof buf - 1;
    applog_write(buf, (size_t)n);
}

void applog_dump(FILE *out) {
    if (!out) out = stdout;
    pthread_mutex_lock(&g.mu);
    if (!g.f) { pthread_mutex_unlock(&g.mu); return; }
    Hdr h = g.h;
    uint8_t *chunk = malloc(PAY);
    if (!chunk) { pthread_mutex_unlock(&g.mu); return; }
    if (fseeko(g.f, HDR, SEEK_SET) != 0) { free(chunk); pthread_mutex_unlock(&g.mu); return; }
    size_t got = fread(chunk, 1, PAY, g.f);
    pthread_mutex_unlock(&g.mu);
    if (got < PAY) memset(chunk + got, 0, PAY - got);
    if (!h.wrapped) {
        fwrite(chunk, 1, (size_t)h.pos, out);
    } else {
        fwrite(chunk + h.pos, 1, PAY - (size_t)h.pos, out);
        fwrite(chunk, 1, (size_t)h.pos, out);
    }
    fflush(out);
    free(chunk);
}

static void *stderr_reader(void *arg) {
    int rfd = (int)(intptr_t)arg;
    char buf[4096];
    for (;;) {
        ssize_t n = read(rfd, buf, sizeof buf);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            break;
        }
        applog_write(buf, (size_t)n);
        if (g.echo >= 0) {
            const char *p = buf;
            size_t left = (size_t)n;
            while (left) {
                ssize_t w = write(g.echo, p, left);
                if (w <= 0) break;
                p += (size_t)w;
                left -= (size_t)w;
            }
        }
    }
    close(rfd);
    return NULL;
}

void applog_hook_stderr(void) {
    if (g.hooked || !g.f) return;
    int fds[2];
#ifdef _WIN32
    if (_pipe(fds, 16384, _O_BINARY) != 0) return;
#else
    if (pipe(fds) != 0) return;
#endif
    int orig = dup(STDERR_FILENO);
    if (dup2(fds[1], STDERR_FILENO) < 0) {
        close(fds[0]); close(fds[1]);
        if (orig >= 0) close(orig);
        return;
    }
    close(fds[1]);
    g.echo = orig;
    setvbuf(stderr, NULL, _IOLBF, 4096);
    if (pthread_create(&g.th, NULL, stderr_reader, (void *)(intptr_t)fds[0]) != 0) {
        close(fds[0]);
        return;
    }
    pthread_detach(g.th);
    g.hooked = 1;
}
