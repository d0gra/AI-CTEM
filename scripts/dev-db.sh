#!/bin/sh
# Start a project-local PostgreSQL (port 54329) and Redis (port 63799) for development without Docker.
# Requires PostgreSQL 17 and Redis binaries on PATH (macOS: brew install postgresql@17 redis).
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA="$ROOT/.local"
PGBIN="${PGBIN:-$(dirname "$(command -v pg_ctl || echo /opt/homebrew/opt/postgresql@17/bin/pg_ctl)")}"
export LC_ALL="${LC_ALL:-en_US.UTF-8}"
mkdir -p "$DATA"
if [ ! -d "$DATA/pgdata" ]; then
  "$PGBIN/initdb" -D "$DATA/pgdata" -U postgres -A trust -E UTF8 >/dev/null
  FIRST_RUN=1
fi
"$PGBIN/pg_ctl" -D "$DATA/pgdata" -o "-p 54329 -c listen_addresses=127.0.0.1" -l "$DATA/pg.log" status >/dev/null 2>&1 ||
  "$PGBIN/pg_ctl" -D "$DATA/pgdata" -o "-p 54329 -c listen_addresses=127.0.0.1" -l "$DATA/pg.log" -w start >/dev/null
if [ "${FIRST_RUN:-0}" = 1 ]; then
  "$PGBIN/psql" -h 127.0.0.1 -p 54329 -U postgres -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE ROLE ctem_owner LOGIN PASSWORD 'ctem_owner_dev';
CREATE ROLE ctem_app LOGIN PASSWORD 'ctem_app_dev' NOSUPERUSER NOBYPASSRLS;
CREATE DATABASE ctem OWNER ctem_owner;
CREATE DATABASE ctem_test OWNER ctem_owner;
SQL
fi
redis-cli -p 63799 ping >/dev/null 2>&1 || redis-server --port 63799 --dir "$DATA" --daemonize yes --save "" >/dev/null
echo "PostgreSQL on 127.0.0.1:54329 (databases ctem, ctem_test); Redis on 127.0.0.1:63799"
echo "These development role passwords are for local use only."
