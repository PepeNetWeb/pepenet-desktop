// favicon.h — Discover's site-icon fetcher (async, best-effort).
//
// A worker thread pulls /favicon.ico (then /favicon.png) for servable sites
// THROUGH THE LOCAL DANE PROXY — the same pin-verified path the browser uses,
// so no favicon byte ever arrives from an unverified origin. Bodies decode
// via stb_image (PNG/JPEG/GIF/BMP + the PNG/32bpp entries of an .ico) into
// RGBA the UI thread turns into textures. Everything is cached for the run:
// one fetch per name, failures stick for ~15 min then retry once per ask.
#ifndef DNET_FAVICON_H
#define DNET_FAVICON_H

#include <stdint.h>

enum { FAV_NONE = 0, FAV_PENDING, FAV_READY, FAV_FAIL };

// Look up (and on first ask, enqueue) `name`'s favicon. Returns the FAV_*
// state; on FAV_READY *rgba/*w/*h describe the decoded image, owned by the
// cache (valid until favicon_stop). UI thread only.
int favicon_query(const char *name, const uint8_t **rgba, int *w, int *h);

void favicon_boot(void);   // start the worker (idempotent; needs the proxy up)
void favicon_stop(void);   // stop + join + free the cache

#endif
