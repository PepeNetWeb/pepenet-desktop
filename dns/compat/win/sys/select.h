/* sys/select.h — Windows stand-in: winsock's select()/fd_set operate on
 * SOCKETs directly (nfds is ignored); the POSIX call shape works unchanged. */
#ifndef DNET_COMPAT_SYS_SELECT_H
#define DNET_COMPAT_SYS_SELECT_H
#include "../dnet_wincompat.h"
#endif
