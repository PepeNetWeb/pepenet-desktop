#!/bin/sh
# Run examples/queries.sql read-only against an indexer db.
# Usage: sh examples/queries.sh <db>   (sqlite3 CLI, or python3 as a fallback)
set -e
DB=${1:?usage: queries.sh <db>}
SQL=$(dirname "$0")/queries.sql
if command -v sqlite3 >/dev/null 2>&1; then
    exec sqlite3 -header "file:$DB?mode=ro" < "$SQL"
fi
exec python3 - "$DB" "$SQL" <<'PY'
import sqlite3, sys
c = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
for stmt in open(sys.argv[2]).read().split(";"):
    body = "\n".join(l for l in stmt.splitlines() if not l.strip().startswith("--")).strip()
    if not body: continue
    cur = c.execute(body)
    print("--", " | ".join(d[0] for d in cur.description))
    for row in cur: print(" | ".join(str(v) for v in row))
PY
