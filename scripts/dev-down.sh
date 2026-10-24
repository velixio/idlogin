#!/bin/sh
# Stops the processes started by scripts/dev-up.sh. Data stays in
# PostgreSQL and in $IDLOGIN_DEV_HOME.
set -eu
RUN="${IDLOGIN_DEV_HOME:-${XDG_DATA_HOME:-$HOME/.local/share}/idlogin}"
for p in idlogin zitadel; do
  if [ -f "$RUN/$p.pid" ]; then
    pid="$(cat "$RUN/$p.pid")"
    # setsid made each process a group leader; stop the whole group.
    kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
    rm -f "$RUN/$p.pid"
    echo "stopped $p"
  fi
done
