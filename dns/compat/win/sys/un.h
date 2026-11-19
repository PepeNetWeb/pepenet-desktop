/* sys/un.h — Windows stand-in: AF_UNIX stream sockets exist since Win10 1803
 * (afunix.h). Only the standalone daemons' ctl channel uses this. */
#ifndef DNET_COMPAT_SYS_UN_H
#define DNET_COMPAT_SYS_UN_H
#include "../dnet_wincompat.h"
#if defined(__has_include) && __has_include(<afunix.h>)
#include <afunix.h>
#else
#define UNIX_PATH_MAX 108
struct sockaddr_un {
    unsigned short sun_family;
    char sun_path[UNIX_PATH_MAX];
};
#endif
#endif
