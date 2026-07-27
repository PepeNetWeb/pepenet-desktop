// update.h — the notify-only update check.
//
// Once a day a worker thread resolves APP_RELEASES_URL "/latest" (GitHub
// 302s it to .../releases/tag/<version>) and compares that tag against the
// compiled-in PEPENET_VERSION. Strictly newer → the footer shows a notice
// that links the user to the releases page. That is ALL it does — nothing is
// downloaded, verified, or executed; the human fetches and installs by hand.
// (Deliberate: an auto-updater is a code-execution channel into a wallet app,
// and without offline-signed manifests it would trust GitHub with exactly the
// power we don't want to grant. Worst case here is a false banner.)
#ifndef DNET_UPDATE_H
#define DNET_UPDATE_H

#include <stddef.h>

// Spawn the daily background check (idempotent; detached thread, no stop —
// it holds no resources that outlive the process).
void update_start(void);

// A release newer than this build is known: 1 + its version string into
// `ver`. 0 = up to date, or no successful check yet. UI thread safe.
int update_available(char *ver, size_t cap);

// The compiled-in version (CMake PEPENET_VERSION) — Settings' About row.
const char *update_build_version(void);

#endif
