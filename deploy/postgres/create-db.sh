#!/bin/sh
# Creates the roles and databases on the local PostgreSQL. Run as a user that
# can `sudo -u postgres`. Idempotent: re-running only resets the passwords to
# the values given. Each part runs only when its password is set:
#
#   ZITADEL_DB_PASSWORD=...      role/database zitadel  (Zitadel)
#   LOGIN_DATABASE_PASSWORD=...  role/database idlogin  (cmd/idlogin, sign-in service)
#
#   ZITADEL_DB_PASSWORD=... LOGIN_DATABASE_PASSWORD=... deploy/postgres/create-db.sh
set -eu

if [ -z "${ZITADEL_DB_PASSWORD:-}" ] && [ -z "${LOGIN_DATABASE_PASSWORD:-}" ]; then
  echo "set ZITADEL_DB_PASSWORD and/or LOGIN_DATABASE_PASSWORD" >&2
  exit 1
fi

# create_db ROLE DB PASSWORD
create_db() {
  sudo -u postgres psql -v ON_ERROR_STOP=1 -q \
    -v role="$1" -v db="$2" -v pw="$3" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN', :'role')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'role') \gexec
ALTER ROLE :"role" WITH LOGIN PASSWORD :'pw';
SELECT format('CREATE DATABASE %I OWNER %I', :'db', :'role')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'db') \gexec
SQL
  echo "role $1 and database $2 ready"
}

if [ -n "${ZITADEL_DB_PASSWORD:-}" ]; then
  create_db "${ZITADEL_DB_USER:-zitadel}" "${ZITADEL_DB_NAME:-zitadel}" "$ZITADEL_DB_PASSWORD"
fi
if [ -n "${LOGIN_DATABASE_PASSWORD:-}" ]; then
  create_db "${LOGIN_DB_USER:-idlogin}" "${LOGIN_DB_NAME:-idlogin}" "$LOGIN_DATABASE_PASSWORD"
fi
