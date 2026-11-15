#!/bin/bash
# Production entrypoint. One image, one of four roles, given as the command:
#
#   all       web, API and worker in this container (the default)
#   serve     web and API only, for when workers run in their own containers
#   worker    background jobs only
#   migrate   apply database migrations, then exit
#
# Any role that runs more than one process exits as soon as one of them does, with that process's
# status, so the orchestrator restarts the container instead of leaving it half-running.
set -euo pipefail

APP=/app/backend
WEB=/app/web
# The web tier proxies /api/* to this address. Next.js compiles the destination into the build, so it is
# fixed: the API runs in this container, beside the web server.
API_PORT=8000
API_BIND=${CTEM_API_BIND:-0.0.0.0}   # 127.0.0.1 keeps the API off the pod network, but also off Prometheus
export PORT=${PORT:-3000}

log() { printf '[ctem %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

pids=()
spawn() { "$@" & pids+=($!); }

shutdown() {
  trap - TERM INT
  [ ${#pids[@]} -eq 0 ] && return 0
  log "stopping"
  kill "${pids[@]}" 2>/dev/null || true
  wait "${pids[@]}" 2>/dev/null || true
}

migrate() {
  log "applying database migrations"
  cd "$APP"
  alembic upgrade head
}

start_api() {
  log "API on $API_BIND:$API_PORT"
  cd "$APP"
  # --no-proxy-headers: the API takes the client address from CTEM_TRUSTED_PROXIES, not from whatever
  # a caller puts in X-Forwarded-For.
  spawn uvicorn app.main:app --host "$API_BIND" --port "$API_PORT" --no-proxy-headers
}

start_worker() {
  log "worker"
  cd "$APP"
  spawn python -m app.workers.runner
}

start_web() {
  log "web on 0.0.0.0:$PORT"
  cd "$WEB"
  spawn env HOSTNAME=0.0.0.0 PORT="$PORT" node server.js
}

role=${1:-all}
case "$role" in
  migrate)
    migrate
    exit 0
    ;;
  all | serve | worker) ;;
  -* | "")
    # Not a role: run it as a command, so `docker run <image> python -m app.cli ...` works.
    exec "$@"
    ;;
  *)
    if command -v "$role" > /dev/null 2>&1; then
      exec "$@"
    fi
    echo "ctem: unknown role '$role'. Use all, serve, worker or migrate, or give a command to run." >&2
    exit 2
    ;;
esac

mkdir -p "${CTEM_STORAGE_LOCAL_PATH:-/app/var/storage}" 2> /dev/null || true

# Off by default: with more than one replica, two containers would migrate at the same time. Run the
# migrate role as a Job or an init container instead.
if [ "${CTEM_AUTO_MIGRATE:-false}" = true ]; then
  migrate
fi

trap 'shutdown; exit 0' TERM INT

case "$role" in
  all)
    start_web
    start_api
    start_worker
    ;;
  serve)
    start_web
    start_api
    ;;
  worker) start_worker ;;
esac

code=0
wait -n || code=$?
log "a process exited with status $code"
shutdown
exit "$code"
