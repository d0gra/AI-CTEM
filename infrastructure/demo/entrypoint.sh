#!/usr/bin/env bash
# All-in-one demo container: PostgreSQL, the API (with the job worker on a thread of the same
# process) and the web server, sized to fit a 512 MB instance such as Render's free plan.
#
# Data lives inside the container, so every restart or redeploy starts from a clean demo. Secrets and
# database passwords are generated at start unless provided. The same script runs outside a container
# for testing: point CTEM_APP_DIR, CTEM_WEB_DIR, PGDATA and PG_BIN at local paths.
set -euo pipefail

APP_DIR=${CTEM_APP_DIR:-/app/backend}
WEB_DIR=${CTEM_WEB_DIR:-/app/web}
VAR_DIR=${CTEM_VAR_DIR:-/app/var}
export PGDATA=${PGDATA:-/var/lib/postgresql/data}
PG_BIN=${PG_BIN:-$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | tail -1)}
PG_PORT=${CTEM_PG_PORT:-5432}
API_PORT=${CTEM_API_PORT:-8000}
export PORT=${PORT:-10000}
export LANG=${LANG:-C.UTF-8} LC_ALL=${LC_ALL:-C.UTF-8}

log() { printf '[demo] %s\n' "$*"; }

# Run as an unprivileged user when started as root (inside the image); as the current user otherwise.
as_user() { local u=$1; shift; if [ "$(id -u)" = 0 ]; then gosu "$u" "$@"; else "$@"; fi; }
PY="$APP_DIR/.venv/bin/python"
random() { "$PY" -c "import secrets; print(secrets.token_urlsafe($1))"; }
pids=()
# Start a long-running process in the background, unprivileged when root, and remember its pid.
spawn() { local u=$1; shift; if [ "$(id -u)" = 0 ]; then gosu "$u" "$@" & else "$@" & fi; pids+=($!); }

# --- Settings -----------------------------------------------------------------------------------
export CTEM_ENV=${CTEM_ENV:-production}
export CTEM_DEMO_MODE=${CTEM_DEMO_MODE:-true}
export CTEM_SECRET_KEY=${CTEM_SECRET_KEY:-$(random 48)}
export CTEM_ENCRYPTION_KEYS=${CTEM_ENCRYPTION_KEYS:-$("$PY" -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")}
export CTEM_PUBLIC_BASE_URL=${CTEM_PUBLIC_BASE_URL:-${RENDER_EXTERNAL_URL:-http://localhost:$PORT}}
export CTEM_COOKIE_SECURE=${CTEM_COOKIE_SECURE:-true}  # browsers accept Secure cookies on http://localhost too
export CTEM_ALLOW_REGISTRATION=${CTEM_ALLOW_REGISTRATION:-false}
export CTEM_ALLOW_PRIVATE_TARGETS=false
export CTEM_STORAGE_LOCAL_PATH=${CTEM_STORAGE_LOCAL_PATH:-$VAR_DIR/storage}
export CTEM_REPO_SCAN_ROOT=${CTEM_REPO_SCAN_ROOT:-$VAR_DIR/repos}
# Memory: one Python process runs both the API and the worker; few database connections (each
# PostgreSQL backend costs several MB); glibc keeps fewer per-thread malloc arenas; capped Node heap.
export CTEM_EMBEDDED_WORKER=${CTEM_EMBEDDED_WORKER:-true}
export CTEM_WORKER_CONCURRENCY=${CTEM_WORKER_CONCURRENCY:-1}
export CTEM_DB_POOL_SIZE=${CTEM_DB_POOL_SIZE:-4}
export CTEM_DB_MAX_OVERFLOW=${CTEM_DB_MAX_OVERFLOW:-3}
export MALLOC_ARENA_MAX=${MALLOC_ARENA_MAX:-2}
export NODE_OPTIONS=${NODE_OPTIONS:---max-old-space-size=96}
export CTEM_LOG_JSON=${CTEM_LOG_JSON:-true}
# The web server is the only caller of the API, from loopback. Render's proxy appends the client address.
export CTEM_TRUSTED_PROXIES=${CTEM_TRUSTED_PROXIES:-127.0.0.1/32,::1/128,10.0.0.0/8}
export CTEM_UPSTREAM_PROXY=${CTEM_UPSTREAM_PROXY:-true}
APP_DB_PASSWORD=$(random 24)
OWNER_DB_PASSWORD=$(random 24)
export CTEM_DATABASE_URL="postgresql+psycopg://ctem_app:$APP_DB_PASSWORD@127.0.0.1:$PG_PORT/ctem"
export CTEM_MIGRATION_DATABASE_URL="postgresql+psycopg://ctem_owner:$OWNER_DB_PASSWORD@127.0.0.1:$PG_PORT/ctem"
mkdir -p "$CTEM_STORAGE_LOCAL_PATH" "$CTEM_REPO_SCAN_ROOT"
[ "$(id -u)" = 0 ] && chown -R ctem "$VAR_DIR"

# --- PostgreSQL ---------------------------------------------------------------------------------
if [ ! -s "$PGDATA/PG_VERSION" ]; then
  log "initialising database"
  mkdir -p "$PGDATA"; [ "$(id -u)" = 0 ] && chown postgres "$PGDATA"
  as_user postgres "$PG_BIN/initdb" -D "$PGDATA" -U postgres --auth-local=trust --auth-host=scram-sha-256 --encoding=UTF8 >/dev/null
fi
SOCKET_DIR=${CTEM_PG_SOCKET_DIR:-/var/run/postgresql}
mkdir -p "$SOCKET_DIR"; [ "$(id -u)" = 0 ] && chown postgres "$SOCKET_DIR"
as_user postgres "$PG_BIN/pg_ctl" -D "$PGDATA" -w -l "$PGDATA/server.log" start -o \
  "-c listen_addresses=127.0.0.1 -p $PG_PORT -k $SOCKET_DIR -c max_connections=12 -c shared_buffers=16MB -c work_mem=2MB -c maintenance_work_mem=16MB -c wal_buffers=1MB -c jit=off -c max_worker_processes=2 -c max_parallel_workers=0 -c max_parallel_workers_per_gather=0 -c autovacuum_max_workers=1 -c wal_level=minimal -c max_wal_senders=0 -c fsync=off -c synchronous_commit=off -c full_page_writes=off" >/dev/null
psql_admin() { as_user postgres "$PG_BIN/psql" -v ON_ERROR_STOP=1 -q -h "$SOCKET_DIR" -p "$PG_PORT" -U postgres "$@"; }
# Two roles, as in production: the owner runs migrations; the app role is subject to row-level security.
psql_admin -d postgres <<SQL
DO \$\$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ctem_owner') THEN CREATE ROLE ctem_owner LOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ctem_app') THEN CREATE ROLE ctem_app LOGIN NOSUPERUSER NOBYPASSRLS; END IF;
END \$\$;
ALTER ROLE ctem_owner PASSWORD '$OWNER_DB_PASSWORD';
ALTER ROLE ctem_app PASSWORD '$APP_DB_PASSWORD';
SQL
psql_admin -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname = 'ctem'" | grep -q 1 || psql_admin -d postgres -c "CREATE DATABASE ctem OWNER ctem_owner"

# --- Application ----------------------------------------------------------------------------------
cd "$APP_DIR"
log "applying migrations"
as_user ctem "$PY" -m alembic upgrade head
if [ "$CTEM_DEMO_MODE" = true ]; then
  log "seeding demo accounts and sample data"
  as_user ctem "$PY" -m app.cli seed-demo
fi

shutdown() {
  log "stopping"
  kill "${pids[@]}" 2>/dev/null || true
  wait "${pids[@]}" 2>/dev/null || true
  as_user postgres "$PG_BIN/pg_ctl" -D "$PGDATA" -m fast stop >/dev/null || true
}
trap 'shutdown; exit 0' TERM INT

spawn ctem "$PY" -m uvicorn app.main:app --host 127.0.0.1 --port "$API_PORT" --no-proxy-headers --no-access-log
[ "$CTEM_EMBEDDED_WORKER" = true ] || spawn ctem "$PY" -m app.workers.runner
cd "$WEB_DIR"
spawn ctem env HOSTNAME=0.0.0.0 PORT="$PORT" CTEM_UPSTREAM_PROXY="$CTEM_UPSTREAM_PROXY" "$(command -v node)" server.js
log "starting on port $PORT ($CTEM_PUBLIC_BASE_URL)"

# If any process exits, stop the rest so the platform restarts the container.
while :; do
  for pid in "${pids[@]}"; do
    if ! kill -0 "$pid" 2>/dev/null; then
      log "process $pid exited; stopping the demo"
      shutdown
      exit 1
    fi
  done
  sleep 2
done
