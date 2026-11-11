# Deployment

## Topology

```
Internet → TLS ingress → web (Next.js) → api (FastAPI) → PostgreSQL / Redis / object storage
                                         workers ──────┘        └→ authorized targets, cloud APIs, intel feeds
```

Only the web tier is exposed. The API should be reachable only from the web tier (see the NetworkPolicy in `infrastructure/kubernetes/ctem.yaml`). Workers need outbound access to assessment targets and to `api.osv.dev`, `www.cisa.gov`, `api.first.org`, `services.nvd.nist.gov`, `crt.sh`, `raw.githubusercontent.com` (ATT&CK/ATLAS), and any configured cloud, ticketing or LLM endpoints.

## Docker Compose (single host)

```bash
cp .env.example .env    # fill in the five required secrets
docker compose up --build -d
docker compose logs -f api worker
```

Put a TLS-terminating reverse proxy in front of port 3000 and keep `CTEM_COOKIE_SECURE=true`. This path was not build-tested during development (no container runtime available); CI builds the images.

## Kubernetes

1. Build and push three images: `docker build --target api`, `--target worker` (from `backend/`) and `frontend/` with `--build-arg CTEM_BACKEND_URL=http://api:8000`.
2. Provision PostgreSQL and create the two roles and the database (README, Database setup).
3. Create `ctem-secrets` from your secret manager; edit `ctem-config`.
4. `kubectl apply -f infrastructure/kubernetes/ctem.yaml`. The migration Job must complete before the API is useful; re-run it on every release before rolling the Deployments.

The manifests run as non-root with a read-only root filesystem, dropped capabilities and the `restricted` Pod Security level. They are reference manifests and have not been applied to a cluster.

## Scaling

- **API** is stateless; scale horizontally. Redis is required with more than one replica so rate limits are shared.
- **Workers** scale horizontally; job claiming is safe under concurrency. `CTEM_WORKER_CONCURRENCY` sets threads per worker; `CTEM_MAX_RUNNING_JOBS_PER_ORG` caps a tenant.
- **Storage** must be shared between API and workers: use `CTEM_STORAGE_BACKEND=s3` (S3, MinIO, Ceph) or a ReadWriteMany volume at `CTEM_STORAGE_LOCAL_PATH`.
- **PostgreSQL**: connection pool is `CTEM_DB_POOL_SIZE` (+10 overflow) per process.

## Scanner tooling in workers

The worker image installs `nmap`. To enable other engines, derive an image that adds the binaries (`nuclei`, `trivy`, `grype`, `semgrep`, `gitleaks`, `checkov`). The Assessments UI and `GET /api/v1/assessments/engines` show which tools the API host has; a run fails with a clear error if the worker lacks the tool. Workers that run active scans should be placed in a network segment appropriate for scanning and be the only component with that egress.

For repository analysis, mount checkouts read-only under a directory and set `CTEM_REPO_SCAN_ROOT` to it on API and workers.

## Observability

- Logs: JSON to stdout with `request_id`, user and organization ids. Secrets are redacted by key name.
- Metrics: `/metrics` on the API (`ctem_http_requests_total`, `ctem_http_request_duration_seconds`) and on workers when `CTEM_WORKER_METRICS_PORT` is set (`ctem_jobs_total`, `ctem_jobs_running`). Protect `/metrics` at the ingress.
- Tracing: set `CTEM_OTEL_EXPORTER_OTLP_ENDPOINT` to an OTLP/HTTP collector to enable FastAPI tracing.
- `infrastructure/monitoring/` contains a Prometheus scrape config, alert rules and a Grafana dashboard.
- Health: `/healthz` (liveness) and `/readyz` (database and Redis). Integration health and threat-intel sync state are visible in the UI and API.

## Backup and recovery

| Data | Method | Notes |
| --- | --- | --- |
| PostgreSQL | `pg_dump -Fc -U ctem_owner ctem` daily plus WAL archiving or provider PITR | Contains everything except binary artifacts |
| Object storage | Bucket versioning and replication, or volume snapshots | Evidence files, scanner uploads, generated reports |
| `CTEM_ENCRYPTION_KEYS`, `CTEM_SECRET_KEY` | Secret manager with its own backup | Losing the encryption keys makes stored integration credentials and MFA secrets unrecoverable |

Restore: create the roles, `pg_restore -d ctem --no-owner --role=ctem_owner`, restore the object store, start the API with the same encryption keys, then run `python -m app.cli verify-audit <org-slug>` for each organization to confirm audit-log integrity. Running jobs at the time of the backup are requeued by the stale-job reaper. Test restores on a schedule; this procedure is documented but has not been rehearsed against a production-sized data set.

## Upgrades

Run `alembic upgrade head` (the `migrate` service or Job) before starting new API and worker versions. Migrations are transactional. Downgrades are provided for the initial schema but should not be relied on for data-bearing releases; restore from backup instead.

## Hardening checklist

- [ ] `CTEM_ENV=production`, unique `CTEM_SECRET_KEY` and `CTEM_ENCRYPTION_KEYS` from a secret manager
- [ ] TLS at the ingress; `CTEM_COOKIE_SECURE=true`
- [ ] Application database role is not owner, not superuser, no `BYPASSRLS`
- [ ] `CTEM_ALLOW_REGISTRATION=false` after onboarding
- [ ] Redis configured; `/metrics` and `/api/docs` not publicly reachable
- [ ] `CTEM_ALLOW_PRIVATE_TARGETS` left `false` unless internal assessment is intended
- [ ] MFA enrolled for administrators
- [ ] Backups and a tested restore
