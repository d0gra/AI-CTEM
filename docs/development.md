# Development

## Setup

```bash
./scripts/dev-db.sh
cd backend && uv sync && uv run alembic upgrade head
cd ../frontend && pnpm install
```

Run the API, a worker and the frontend as described in the README (`make api`, `make worker`, `make web`). `make lab` starts practice targets.

## Conventions

- **Backend.** Each domain package has `router.py` (HTTP, schemas, permission checks) and `service.py` (logic). Routers never build SQL for another domain's tables when a service function exists. Raise `AppError` subclasses; never return ad-hoc error shapes. Line length 120; `ruff check` must pass.
- **Tenant data.** New tables that belong to a tenant use `TenantMixin` and must be added to an RLS migration. Use `Db` (tenant session) in routes. `system_session()` is for authentication lookups, job dispatch and global data only.
- **Outbound HTTP.** Always `core.net.safe_fetch` or `integrations.base.HttpApi`. Do not import `httpx` or `requests` directly in engines.
- **Findings.** Produce `FindingInput` and call the engine context or `findings.service.ingest`. Choose `confidence` honestly: `confirmed` only when the engine observed the weakness directly.
- **Frontend.** Data access through `useGet` / `useAction`; tables through `DataTable`; forms with business rules use a Zod schema in `lib/schemas.ts`. No hardcoded numbers on dashboards.

## Adding an assessment engine

```python
class MyConfig(BaseModel):
    depth: int = Field(default=1, ge=1, le=3)

def run(ctx: EngineContext) -> None:
    for target in ctx.targets:
        decision = ctx.scope(target.value, active=True)      # raises OutOfScope
        if ctx.dry_run:
            ctx.planned(f"Would assess {target.value}")
            continue
        asset = ctx.asset(AssetSpec(type="website", identifier=target.value))
        ctx.finding(FindingInput(asset=asset, source=ctx.source, rule_id="my.rule", domain="web",
                                 title="...", severity="medium", evidence=[EvidenceInput("http_exchange", "...", {...})]))
        ctx.mark_complete(asset)                              # enables retest reconciliation

register(EngineSpec(kind="my_engine", name="My engine", module="web_api", run=run,
                    description="...", config_model=MyConfig, target_kinds=("url",), active=True))
```

Import the module from `app/engines/registry.py`. The UI picks the engine up from `/assessments/engines` and renders the configuration form from the schema.

## Tests

- Backend tests need PostgreSQL (`scripts/dev-db.sh`). Each test registers its own organization, so tests are isolated by tenancy rather than truncation and can share a database.
- `drain()` runs queued jobs through the same `claim`/`execute` path as the worker.
- `site` is a loopback HTTP server with mutable routes; `allow_private` enables private targets for a test.
- External services are replaced with `httpx.MockTransport` (`intel.TRANSPORT`, `llm.TRANSPORT`) or moto.
- Add an isolation assertion to `test_isolation_security.py` for every new resource type.

```bash
cd backend && uv run pytest -k workflow      # subset
cd frontend && pnpm test
```

## Checks before a pull request

```bash
cd backend && uv run ruff check . && uv run alembic check && uv run pytest
cd frontend && pnpm lint && pnpm typecheck && pnpm test && pnpm build
```

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| Migration fails: `Application role ctem_app does not exist` | Create the owner and runtime roles (see `scripts/dev-db.sh` or `infrastructure/docker/postgres/10-roles.sh`), or set `CTEM_APP_DB_ROLE`. |
| Sign-in succeeds but every request returns 401 over plain HTTP | The session cookie is `Secure`. Use HTTPS, or set `CTEM_COOKIE_SECURE=false` for local use. |
| `CSRF token missing or invalid` from a script | Scripts should send `Authorization: Bearer <access_token>` instead of the cookie. |
| Assessment stays *queued* | No worker is running, or the organization is at `CTEM_MAX_RUNNING_JOBS_PER_ORG`. |
| `Target ... is not covered by an authorized scope entry` | Add the target under Administration → Authorized scope. Active engines also need *active testing*. |
| `Destination address ... is not publicly routable` | Private targets need both the scope entry's *private network* flag and `CTEM_ALLOW_PRIVATE_TARGETS=true` on API and workers. |
| `Required tool 'trivy' is not installed on this worker` | Install the binary in the worker image; the engine list shows what each worker has. |
| PostgreSQL refuses to start on macOS: `postmaster became multithreaded` | Start it with `LC_ALL=en_US.UTF-8` (handled by `scripts/dev-db.sh`). |
| Registration rejects an address at `.test` or `.example` | Reserved domains fail email validation; use a real domain or `example.com`. |
