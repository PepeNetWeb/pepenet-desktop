/* libgen.h — Windows stand-in: dirname handling both separators (in-place,
 * POSIX contract: may modify its argument, returns a pointer into it). */
#ifndef DNET_COMPAT_LIBGEN_H
#define DNET_COMPAT_LIBGEN_H
#include "dnet_wincompat.h"

#ifndef DNET_WINCOMPAT_NO_MACROS
#define dirname(p) dnet_dirname(p)
#endif

#endif
