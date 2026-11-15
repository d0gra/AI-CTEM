# syntax=docker/dockerfile:1.7
# The production image. One image, one package; the role is the command:
#
#   docker run ghcr.io/d0gra/ai-ctem:0.3.0 migrate   apply database migrations, then exit
#   docker run ghcr.io/d0gra/ai-ctem:0.3.0 all       web, API and worker in this container (the default)
#   docker run ghcr.io/d0gra/ai-ctem:0.3.0 serve     web and API only, when workers run in their own containers
#   docker run ghcr.io/d0gra/ai-ctem:0.3.0 worker    background jobs only
#
# PostgreSQL and Redis are external: see docker-compose.yml and infrastructure/kubernetes/ctem.yaml.
# Dockerfile.demo is a different image for a different purpose — it bundles PostgreSQL and seeds shared
# accounts for the public demo, and is never published or used in production.

FROM node:22-bookworm-slim AS web
WORKDIR /src
RUN corepack enable
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY frontend/ ./
# The browser only ever talks to the web tier, which proxies /api/* to the API so the session cookie is
# same-origin and no CORS is needed. Next.js resolves this destination at build time into the route
# manifest, which is why the API always runs beside the web server in this image rather than elsewhere.
ENV CTEM_BACKEND_URL=http://127.0.0.1:8000 NEXT_TELEMETRY_DISABLED=1
RUN pnpm build

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy \
    NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 LANG=C.UTF-8 PORT=3000 \
    PATH="/app/backend/.venv/bin:$PATH"
WORKDIR /app/backend

COPY --from=ghcr.io/astral-sh/uv:0.12 /uv /usr/local/bin/uv
COPY --from=node:22-bookworm-slim /usr/local/bin/node /usr/local/bin/node
# nmap is the only scanner an engine executes itself; the rest (nuclei, trivy, grype, semgrep, gitleaks,
# checkov) are optional and left out — install them in a derived image to enable those engines.
# `node --version` fails the build here rather than at start-up if the copied binary cannot run.
RUN apt-get update && apt-get install -y --no-install-recommends nmap \
 && rm -rf /var/lib/apt/lists/* \
 && node --version

COPY backend/pyproject.toml backend/uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project && rm -rf /root/.cache
COPY backend/alembic.ini ./
COPY backend/migrations ./migrations
COPY backend/app ./app
# Compile now: the runtime user cannot write __pycache__, so every start would otherwise recompile.
RUN python -m compileall -q app migrations

COPY --from=web /src/.next/standalone /app/web
COPY --from=web /src/.next/static /app/web/.next/static
COPY --from=web /src/public /app/web/public
COPY infrastructure/docker/entrypoint.sh /usr/local/bin/ctem

RUN useradd --system --uid 10001 --home-dir /app ctem \
 && mkdir -p /app/var/storage /app/var/repos /app/web/.next/cache \
 && chown -R ctem /app/var /app/web/.next/cache \
 && chmod 0755 /usr/local/bin/ctem

USER 10001
EXPOSE 3000 8000
# No HEALTHCHECK: what is healthy depends on the role, and a check of the web port would fail a worker
# container. docker-compose.yml and the Kubernetes manifests define the probe for the role they run.
ENTRYPOINT ["ctem"]
CMD ["all"]
