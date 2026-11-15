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

1. Use the released images, `ghcr.io/d0gra/ai-ctem/{api,worker,web}:<version>` (the manifests reference them), or build your own: `docker build --target api`, `--target worker` (from `backend/`) and `frontend/` with `--build-arg CTEM_BACKEND_URL=http://api:8000`. The released `web` image is built for an API reachable at `http://api:8000`.
2. Provision PostgreSQL and create the two roles and the database (README, Database setup).
3. Create `ctem-secrets` from your secret manager; edit `ctem-config`.
4. `kubectl apply -f infrastructure/kubernetes/ctem.yaml`. The migration Job must complete before the API is useful; re-run it on every release before rolling the Deployments.

The manifests run as non-root with a read-only root filesystem, dropped capabilities and the `restricted` Pod Security level. They are reference manifests and have not been applied to a cluster.

## Client addresses

Rate limits and the audit log use the client's address. The API reads it from `X-Forwarded-For` only when the request arrives from an address in `CTEM_TRUSTED_PROXIES` (the web tier), walking the header from the right and skipping trusted hops.

- **Behind a load balancer, ingress or nginx (recommended, and required for TLS):** make it append the client address (`proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` in nginx; ALB and most ingress controllers do this by default), set `CTEM_UPSTREAM_PROXY=true` on the web tier, and add any further proxy hops between that proxy and the web tier to `CTEM_TRUSTED_PROXIES`.
- **Web server exposed directly:** leave `CTEM_UPSTREAM_PROXY=false`. The web server then strips client-supplied `X-Forwarded-For`, so clients cannot choose their address. Every request then appears to come from the web server, which means rate limits are shared by all users; per-account lockout still applies.

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

## Data retention

A daily job per organization (`platform.retention`) removes operational records past their retention period. Each period is in days, and `0` keeps that kind of record forever.

| Setting | Default | Removes |
| --- | --- | --- |
| `CTEM_RETENTION_JOBS_DAYS` | 30 | Finished background jobs (succeeded, failed, dead-lettered, cancelled) |
| `CTEM_RETENTION_SESSIONS_DAYS` | 30 | Sessions that expired or were revoked, and expired one-time links |
| `CTEM_RETENTION_NOTIFICATIONS_DAYS` | 180 | Notifications with their read marks and delivery records |
| `CTEM_RETENTION_ASSET_OBSERVATIONS_DAYS` | 365 | Repeat "observed" events of assets; first discovery, changes, stale marks and manual edits are kept |
| `CTEM_RETENTION_REPORTS_DAYS` | 365 | Generated report files and their records |
| `CTEM_RETENTION_UPLOADS_DAYS` | 90 | Stored copies of uploaded scanner reports; the findings they produced are kept |

Retention never removes assets, findings, evidence, finding history, risk decisions or policies, and the audit log is kept for the life of the organization (the application role cannot delete from it). Each purge that removes anything is itself recorded in the audit log as `retention.purged` with the counts.

```bash
python -m app.cli purge-expired                                      # apply the periods now, for every organization
python -m app.cli export-organization <org-slug> export.json         # everything stored for an organization, without credentials
python -m app.cli delete-organization <org-slug> --confirm <org-slug>  # permanent: all rows and stored files
```

`delete-organization` connects as the schema owner (`CTEM_MIGRATION_DATABASE_URL`), because the application role is not allowed to delete an organization or any audit record. Export first if the data may be needed.

## Releases

Pushing a tag `vX.Y.Z` runs `.github/workflows/release.yml`: it checks that the backend, frontend, Kubernetes manifests and changelog all declare that version (`scripts/check_versions.py`), builds the `api`, `worker`, `web` and `demo` images, pushes them to GitHub Container Registry with build provenance and an SBOM attestation, and opens a GitHub release from the changelog entry. Verify an image with `gh attestation verify oci://ghcr.io/d0gra/ai-ctem/api:<version> --owner d0gra`. Running the workflow by hand builds the images without pushing. The CLI is released separately with `cli-v*` tags.

Between releases, CI publishes the images it has already built and tested from every push to `main`, tagged `main` and `sha-<commit>`:

```
ghcr.io/d0gra/ai-ctem/{api,worker,web,demo}:main
```

They are pushed only after the demo smoke test and the browser tests pass in the same job, so a broken image is never published, and only from `main` — a pull request is not given a token that can write packages. They carry no provenance or SBOM attestation and `latest` is never moved to them, so prefer a released version in production and use these for staging or for following `main`.

**The first push creates the packages as private.** Until someone opens each package on GitHub and either makes it public or grants the deploying account read access, `docker pull` fails with `denied`, and a Kubernetes node needs an `imagePullSecret`.

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
