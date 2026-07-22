/* sys/socket.h — Windows stand-in (see ../dnet_wincompat.h). The socket-call
 * macros are defined AFTER winsock2's own declarations (pulled in by the core
 * header), so they only rewrite call sites in the including TU. The
 * close/read/write trio lives in the shadowed unistd.h instead — MinGW's real
 * unistd.h declares those names, and a dep source may include it after us. */
#ifndef DNET_COMPAT_SYS_SOCKET_H
#define DNET_COMPAT_SYS_SOCKET_H
#include "../dnet_wincompat.h"

#ifndef DNET_WINCOMPAT_NO_MACROS
#define socket(a, t, p)              dnet_socket((a), (t), (p))
#define accept(f, sa, l)             dnet_accept((f), (sa), (l))
#define connect(f, sa, l)            dnet_connect((f), (sa), (l))
#define setsockopt(f, l, o, v, n)    dnet_setsockopt((f), (l), (o), (v), (n))
#define getsockopt(f, l, o, v, n)    dnet_getsockopt((f), (l), (o), (v), (n))
#define fcntl                        dnet_fcntl
#endif

#endif
