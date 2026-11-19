/* netdb.h — Windows stand-in: getaddrinfo via ws2tcpip (wrapped so WSAStartup
 * has run before the first resolve). */
#ifndef DNET_COMPAT_NETDB_H
#define DNET_COMPAT_NETDB_H
#include "dnet_wincompat.h"

#ifndef DNET_WINCOMPAT_NO_MACROS
#define getaddrinfo(n, s, h, r) dnet_getaddrinfo((n), (s), (h), (r))
#endif

#endif
