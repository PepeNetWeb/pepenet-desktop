/* unistd.h — Windows shim over the real MinGW header. The fd-routed
 * close/read/write call-site macros live HERE (after the real declarations,
 * so they never mangle a prototype): the wrappers detect CRT file fds and
 * route them to _close/_read/_write, everything else to Winsock. */
#ifndef DNET_COMPAT_UNISTD_H
#define DNET_COMPAT_UNISTD_H
#include_next <unistd.h>
#include "dnet_wincompat.h"

#ifndef DNET_WINCOMPAT_NO_MACROS
#define close(f)       dnet_close(f)
#define read(f, b, n)  dnet_read((f), (b), (n))
#define write(f, b, n) dnet_write((f), (b), (n))
#endif

#endif
