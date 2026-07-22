// dnet_wincompat.h — the Windows half of the POSIX seam. The dependency
// submodules (dns/, tls/, indexer/) and the desktop's own network TUs are
// written against BSD sockets + POSIX fds; on Windows this directory is added
// to the include path so their unchanged `#include <sys/socket.h>` etc. land
// on the thin headers here, each of which routes into this one. The wrappers
// keep the POSIX shape the code expects:
//   - sockets stay plain `int` fds with -1 sentinels (SOCKET values truncate
//     to int; Windows kernel handles fit),
//   - close/read/write work on BOTH sockets and CRT file fds (CRT fds are
//     detected via _get_osfhandle and win, so file IO is never misrouted),
//   - connect sets errno=EINPROGRESS on WSAEWOULDBLOCK (the nonblocking-dial
//     idiom in wallet.c / sync.c),
//   - setsockopt converts SO_RCVTIMEO/SO_SNDTIMEO struct timeval → DWORD ms,
//   - poll is WSAPoll, fcntl(F_SETFL, O_NONBLOCK) is ioctlsocket(FIONBIO).
// WSAStartup runs lazily inside socket()/getaddrinfo() — no init call needed.
#ifndef DNET_WINCOMPAT_H
#define DNET_WINCOMPAT_H
#ifdef _WIN32

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <errno.h>
#include <stdint.h>
#include <sys/types.h>   /* ssize_t */
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

void    dnet_wsa_init(void);
int     dnet_socket(int af, int type, int proto);
int     dnet_accept(int fd, struct sockaddr *sa, socklen_t *len);
int     dnet_connect(int fd, const struct sockaddr *sa, socklen_t len);
int     dnet_close(int fd);
ssize_t dnet_read(int fd, void *buf, size_t n);
ssize_t dnet_write(int fd, const void *buf, size_t n);
int     dnet_setsockopt(int fd, int level, int opt, const void *val, socklen_t len);
int     dnet_getsockopt(int fd, int level, int opt, void *val, socklen_t *len);
int     dnet_poll(struct pollfd *fds, unsigned long n, int timeout_ms);
int     dnet_fcntl(int fd, int cmd, ...);
int     dnet_getaddrinfo(const char *node, const char *svc,
                         const struct addrinfo *hints, struct addrinfo **res);
int     dnet_flock(int fd, int op);

/* real symbols (missing from MinGW, name is free): */
int     getentropy(void *buf, size_t n);          /* BCryptGenRandom */
char   *dnet_dirname(char *path);                 /* handles '/' and '\' */

#ifndef timegm
#define timegm _mkgmtime
#endif

/* flock op flags (the call-site macro lives in sys/file.h) */
#ifndef LOCK_SH
#define LOCK_SH 1
#define LOCK_EX 2
#define LOCK_NB 4
#define LOCK_UN 8
#endif

/* fcntl shim surface (only the O_NONBLOCK dance is supported) */
#ifndef F_GETFL
#define F_GETFL 3
#define F_SETFL 4
#endif
#ifndef O_NONBLOCK
#define O_NONBLOCK 0x40000000    /* out of MinGW's O_* range; shim-local flag */
#endif

#ifndef EINPROGRESS
#define EINPROGRESS 112          /* UCRT defines it; belt and braces */
#endif

#ifdef __cplusplus
}
#endif

#endif /* _WIN32 */
#endif
