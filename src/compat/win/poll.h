/* poll.h — Windows stand-in: poll() is WSAPoll (struct pollfd/POLLIN come
 * from winsock2.h). See sys/socket.h sibling for the rest of the seam. */
#ifndef DNET_COMPAT_POLL_H
#define DNET_COMPAT_POLL_H
#include "dnet_wincompat.h"

typedef unsigned long nfds_t;

#ifndef DNET_WINCOMPAT_NO_MACROS
#define poll(f, n, t) dnet_poll((f), (n), (t))
#endif

#endif
