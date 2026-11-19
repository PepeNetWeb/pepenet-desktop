// win_compat.c — implementation of the POSIX-over-Winsock seam declared in
// compat/win/dnet_wincompat.h. Compiled on Windows only.
//
// fd routing rule: CRT file fds win. A descriptor that _get_osfhandle
// recognizes is a CRT fd (files land there, sockets never do), so
// close/read/write route to _close/_read/_write; anything else is treated as
// a SOCKET. This keeps the one ambiguous overlap (a small SOCKET value that
// collides with an open CRT fd number) resolved in the safe direction —
// file IO is never sent to Winsock.
#ifdef _WIN32

#define DNET_WINCOMPAT_NO_MACROS
#include "win/dnet_wincompat.h"

#include <windows.h>
#include <bcrypt.h>
#include <io.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

// ── lazy Winsock init ─────────────────────────────────────────────────────────
static INIT_ONCE g_wsa_once = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK wsa_init_cb(PINIT_ONCE once, PVOID param, PVOID *ctx) {
    (void)once; (void)param; (void)ctx;
    WSADATA wd;
    WSAStartup(MAKEWORD(2, 2), &wd);
    return TRUE;
}
void dnet_wsa_init(void) {
    InitOnceExecuteOnce(&g_wsa_once, wsa_init_cb, NULL, NULL);
}

static int is_crt_fd(int fd) {
    if (fd < 0) return 0;
    // sockets are never in the CRT fd table; suppress the invalid-parameter
    // assert UCRT would raise for out-of-range fds
    intptr_t h = (fd < 4096) ? _get_osfhandle(fd) : (intptr_t)INVALID_HANDLE_VALUE;
    return h != (intptr_t)INVALID_HANDLE_VALUE;
}

static void set_errno_wsa(void) {
    int e = WSAGetLastError();
    switch (e) {
        case WSAEWOULDBLOCK: errno = EWOULDBLOCK; break;
        case WSAEINTR:       errno = EINTR; break;
        case WSAECONNRESET:  errno = ECONNRESET; break;
        case WSAECONNREFUSED:errno = ECONNREFUSED; break;
        case WSAETIMEDOUT:   errno = ETIMEDOUT; break;
        case WSAEADDRINUSE:  errno = EADDRINUSE; break;
        default:             errno = EIO; break;
    }
}

// ── sockets ───────────────────────────────────────────────────────────────────
int dnet_socket(int af, int type, int proto) {
    dnet_wsa_init();
    SOCKET s = socket(af, type, proto);
    if (s == INVALID_SOCKET) { set_errno_wsa(); return -1; }
    return (int)s;
}

int dnet_accept(int fd, struct sockaddr *sa, socklen_t *len) {
    SOCKET c = accept((SOCKET)fd, sa, (int *)len);
    if (c == INVALID_SOCKET) { set_errno_wsa(); return -1; }
    return (int)c;
}

int dnet_connect(int fd, const struct sockaddr *sa, socklen_t len) {
    int r = connect((SOCKET)fd, sa, (int)len);
    if (r != 0) {
        // the POSIX nonblocking-dial idiom: callers expect EINPROGRESS then
        // poll(POLLOUT) + getsockopt(SO_ERROR)
        if (WSAGetLastError() == WSAEWOULDBLOCK) errno = EINPROGRESS;
        else set_errno_wsa();
        return -1;
    }
    return 0;
}

int dnet_close(int fd) {
    if (is_crt_fd(fd)) return _close(fd);
    if (closesocket((SOCKET)fd) != 0) { set_errno_wsa(); return -1; }
    return 0;
}

ssize_t dnet_read(int fd, void *buf, size_t n) {
    if (is_crt_fd(fd)) return _read(fd, buf, (unsigned)n);
    int r = recv((SOCKET)fd, (char *)buf, (int)(n > INT_MAX ? INT_MAX : n), 0);
    if (r == SOCKET_ERROR) { set_errno_wsa(); return -1; }
    return r;
}

ssize_t dnet_write(int fd, const void *buf, size_t n) {
    if (is_crt_fd(fd)) return _write(fd, buf, (unsigned)n);
    int r = send((SOCKET)fd, (const char *)buf, (int)(n > INT_MAX ? INT_MAX : n), 0);
    if (r == SOCKET_ERROR) { set_errno_wsa(); return -1; }
    return r;
}

int dnet_setsockopt(int fd, int level, int opt, const void *val, socklen_t len) {
    // Winsock's SO_RCVTIMEO/SO_SNDTIMEO take DWORD milliseconds, not timeval
    if (level == SOL_SOCKET && (opt == SO_RCVTIMEO || opt == SO_SNDTIMEO) &&
        len == (socklen_t)sizeof(struct timeval)) {
        const struct timeval *tv = (const struct timeval *)val;
        DWORD ms = (DWORD)(tv->tv_sec * 1000 + tv->tv_usec / 1000);
        int r = setsockopt((SOCKET)fd, level, opt, (const char *)&ms, sizeof ms);
        if (r != 0) { set_errno_wsa(); return -1; }
        return 0;
    }
    int r = setsockopt((SOCKET)fd, level, opt, (const char *)val, (int)len);
    if (r != 0) { set_errno_wsa(); return -1; }
    return 0;
}

int dnet_getsockopt(int fd, int level, int opt, void *val, socklen_t *len) {
    int wlen = len ? (int)*len : 0;
    int r = getsockopt((SOCKET)fd, level, opt, (char *)val, &wlen);
    if (r != 0) { set_errno_wsa(); return -1; }
    if (len) *len = (socklen_t)wlen;
    return 0;
}

int dnet_poll(struct pollfd *fds, unsigned long n, int timeout_ms) {
    dnet_wsa_init();
    int r = WSAPoll(fds, (ULONG)n, timeout_ms);
    if (r == SOCKET_ERROR) { set_errno_wsa(); return -1; }
    return r;
}

// fcntl: only the F_GETFL→F_SETFL O_NONBLOCK round-trip the codebase uses.
// F_GETFL reports 0 (blocking); F_SETFL applies FIONBIO from the flag word —
// so the restore call (F_SETFL with the saved 0) re-enables blocking mode.
int dnet_fcntl(int fd, int cmd, ...) {
    if (cmd == F_GETFL) return 0;
    if (cmd == F_SETFL) {
        va_list ap;
        va_start(ap, cmd);
        long flags = va_arg(ap, long);
        va_end(ap);
        u_long nb = (flags & O_NONBLOCK) ? 1 : 0;
        if (ioctlsocket((SOCKET)fd, FIONBIO, &nb) != 0) { set_errno_wsa(); return -1; }
        return 0;
    }
    errno = EINVAL;
    return -1;
}

int dnet_getaddrinfo(const char *node, const char *svc,
                     const struct addrinfo *hints, struct addrinfo **res) {
    dnet_wsa_init();
    return getaddrinfo(node, svc, hints, res);
}

// ── flock (LockFileEx; advisory whole-file lock on a CRT fd) ──────────────────
int dnet_flock(int fd, int op) {
    HANDLE h = (HANDLE)_get_osfhandle(fd);
    if (h == INVALID_HANDLE_VALUE) { errno = EBADF; return -1; }
    OVERLAPPED ov;
    memset(&ov, 0, sizeof ov);
    if (op & LOCK_UN) {
        if (!UnlockFileEx(h, 0, MAXDWORD, MAXDWORD, &ov)) { errno = EIO; return -1; }
        return 0;
    }
    DWORD flags = (op & LOCK_EX) ? LOCKFILE_EXCLUSIVE_LOCK : 0;
    if (op & LOCK_NB) flags |= LOCKFILE_FAIL_IMMEDIATELY;
    if (!LockFileEx(h, flags, 0, MAXDWORD, MAXDWORD, &ov)) {
        errno = (GetLastError() == ERROR_LOCK_VIOLATION) ? EWOULDBLOCK : EIO;
        return -1;
    }
    return 0;
}

// ── getentropy (CSPRNG — seeds private keys; BCrypt system-preferred RNG) ─────
int getentropy(void *buf, size_t n) {
    if (n > 256) { errno = EIO; return -1; }
    NTSTATUS st = BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)n,
                                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (st != 0) { errno = EIO; return -1; }
    return 0;
}

// ── dirname (both separators; POSIX contract: may edit its argument) ──────────
char *dnet_dirname(char *path) {
    static char dot[] = ".";
    if (!path || !*path) return dot;
    char *a = strrchr(path, '/');
    char *b = strrchr(path, '\\');
    char *sep = (a && b) ? (a > b ? a : b) : (a ? a : b);
    if (!sep) return dot;
    if (sep == path) { sep[1] = 0; return path; }   // "/x" → "/"
    *sep = 0;
    return path;
}

#endif /* _WIN32 */
