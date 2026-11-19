# Pinned sqlite for reproducible snapshots

The whole-file snapshot pin (idx-04/06) is **specific to the sqlite version**.
The same db, put through the same canonical export, gave a different
state.db sha256 for each sqlite version tested on the regtest fixture
(idx-06/07, Oct 26 2026):

| sqlite | fixture state.db sha256 |
|---|---|
| 3.46.1 (system libsqlite3, Debian) | 41149aa8c96fe4800f28fa53a2bace7deb2fdc3c0ad484d86c98e7197c43ea4a |
| 3.53.2 (vendored amalgamation) | 16b309a7214d9a46bb3c422140f1b2488379942df10add840030d7828bbba7ff |
| 3.54.1 (vendored amalgamation) | b76482b3da89ada584a15e8b5c32abfda0c96a02d0564593328d12b03e99e16f |

One known cause is that the file header records the writing library's
version number (the "version-valid-for" field at offset 92 and the
SQLITE_VERSION_NUMBER at offset 96). Whether the page bodies also differ has
not been checked. Either way, the publisher and every reproducer must build
with the same sqlite version, and `snapshot-export` prints the version it
used.

## Build option
The default is unchanged (system sqlite via pkg-config). For a pinned build:
```
make SQLITE_AMALGAMATION=/path/to/sqlite-amalgamation-3540100 \
     SQLITE_PIN_VERSION=3.54.1 \
     SQLITE_PIN_SHA256=0c657666d819f261cc4007526ad57e1669de9949df7a8ea847aa284a2bf0ee52
```
This compiles `sqlite3.c` statically into `build/sqlite/sqlite3.o`. The
build stops if the header version or the sha256 of `sqlite3.c` doesn't match
the pin. Nothing is downloaded and nothing is vendored into the repo yet.

## Recommendation (proposal; decision for nowon + Best In Show)
* **Option A: current upstream, 3.54.1** (released 2026-10-16).
  * `sqlite-amalgamation-3540100.zip`:
    * sha256 `0a9c8e34352dad46006aa82836d5383bff9dc6bc9ce5a60553c05aa30e6ad1f9`
    * SHA3-256 `92281c86e2957f9b9305890f9ac04204caa7b677cc868dc326d942689df28e30`
      (this matches sqlite.org/download.html, checked Oct 26 2026)
  * `sqlite3.c` sha256 `0c657666d819f261cc4007526ad57e1669de9949df7a8ea847aa284a2bf0ee52`
  * `sqlite3.h` sha256 `d6c84557261893439b341d2e6c35187ae3ea24fbfd843ad94616f72d89242b8c`
  * SOURCE_ID `2026-10-16 14:45:20 555e07ef33f69a0957d24d8e555b702464a131d6f1607f4c3c1e4551e8e6ca76`
* **Option B: match the Firefox ESR in Dane, 3.53.2.** The GreatDANE tree
  at /workspace/ff (ESR 153.7.0, obj-gd build) ships
  `third_party/sqlite3/src/sqlite3.h` 3.53.2, and its built
  `libmozsqlite3.so` reports 3.53.2. The box's system firefox-esr 153.5.1
  also reports 3.53.2. Mozilla's `sqlite3.c` is **not** byte-identical to
  upstream (sha256 582265b9…5b7de7e vs upstream 0a409f16…4667f5e23d), but
  `sqlite3.h` is identical (9e69a135…0b5edb26).
  * Upstream `sqlite-amalgamation-3530200.zip`:
    * sha256 `8a310d0a16c7a90cacd4c884e70faa51c902afed2a89f63aaa0126ab83558a32`
    * SHA3-256 `81142986038e18f96c4a54e1a72562ae17e502a916f2a7701eff43388cbf1a40`
      (this one is not cross-checked against an official listing, because the
      download page only lists the current release)
  * `sqlite3.c` sha256 `0a409f1633283fa31a9126b11fbfd64a1991c5d30defad07e5745d4667f5e23d`
* My recommendation is **3.54.1**, pinned by sha256 of `sqlite3.c`. The
  indexer links it statically, so it does not have to match Firefox's copy;
  the two never share a db file. Choose 3.53.2 only if Best In Show wants a
  single sqlite version across the bundle. Either way, a sqlite bump changes
  the pin and must ship together with a new snapshot.

## idx-09: greatdane-node and the desktop test suites

The same three switches work for the embedded node (CMake) and `test/` (make):

    cmake -S . -B build -DSQLITE_AMALGAMATION=<dir> -DSQLITE_PIN_VERSION=3.54.1 \
          -DSQLITE_PIN_SHA256=0c657666d819f261cc4007526ad57e1669de9949df7a8ea847aa284a2bf0ee52
    make -C test check SQLITE_AMALGAMATION=<dir> SQLITE_PIN_VERSION=3.54.1 SQLITE_PIN_SHA256=...

CMake checks the version/sha at configure time and links the `sqlite3_pinned`
static target into greatdane-node only; `pepenet-desktop` (GUI) still links the
platform sqlite. `test/` reuses the indexer's checked `build/sqlite/sqlite3.o`.
Unset = the previous platform default on every OS.

Decision: the publisher's exporter and Dane's node use upstream 3.54.1. Firefox
keeps its own bundled 3.53.2; the two never open the same db.

## Portability (idx-10)

- The pin check uses `sha256sum`, falls back to `shasum -a 256` (macOS), and
  fails clearly if neither exists.
- `-ldl` is linked only off Windows (`SQLITE_DL` is empty when `OS=Windows_NT`
  or `uname` reports MINGW/MSYS/CYGWIN), so MinGW builds link.
- The MANIFEST is written with "wb", so it has LF line endings on Windows too.
- Only Linux was built and tested. MinGW and macOS are handled in the Makefiles
  but not built here, and MSVC is not covered.

## Link hooks (idx-11)

`indexer/Makefile` and `test/Makefile` take two extra variables:

- `EXTRA_LDFLAGS` is added to the link flags, before the objects. Example: `-static`.
- `EXTRA_LIBS` is added last on every link line. Example: `-lm`.

Example static build:

    make EXTRA_LDFLAGS=-static EXTRA_LIBS=-lm SQLITE_AMALGAMATION=...

Do not use `make LIBS+=...` or `make LDLIBS=...`. A command-line assignment
replaces the Makefile's value, which drops libsecp256k1, sqlite and -lpthread.
`LDFLAGS` given on the command line is still honoured.

A static glibc build works: indexerd links and its selftest passes. The linker
warns that `getaddrinfo` needs the glibc shared libraries at runtime.
