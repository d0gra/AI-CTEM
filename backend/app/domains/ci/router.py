"""CI/CD ingestion.

Pipelines authenticate with an organization CI token (`Authorization: Bearer ctem_ci_...`). The
token can only upload scanner reports and read back the result of its own uploads; it cannot use
any other part of the API.
"""

import asyncio
import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from starlette.concurrency import run_in_threadpool

from app.api.deps import Db, Paging, Principal, audit_event, paginate, require
from app.core.clientip import client_ip
from app.core.config import get_settings
from app.core.errors import NotFound, Unauthorized, ValidationFailed
from app.core.security import hash_token, new_token
from app.db.base import utcnow
from app.db.session import system_session, tenant_session
from app.domains.assessments.service import start_run
from app.domains.audit import service as audit
from app.domains.ci import service
from app.models import ApiToken, Assessment, AssessmentRun
from app.workers.queue import claim, execute

router = APIRouter(tags=["CI/CD"])
TOKEN_PREFIX = "ctem_ci_"  # noqa: S105  (public prefix, not a secret)


@dataclass
class CiCaller:
    token_id: uuid.UUID
    organization_id: uuid.UUID
    name: str


def ci_caller(request: Request) -> CiCaller:
    header = request.headers.get("authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else ""
    if not token.startswith(TOKEN_PREFIX):
        raise Unauthorized("A CI token is required (Authorization: Bearer ctem_ci_...)")
    now = utcnow()
    with system_session() as db:
        row = db.execute(select(ApiToken).where(ApiToken.token_hash == hash_token(token))).scalar_one_or_none()
        if row is None or row.revoked_at is not None or (row.expires_at and row.expires_at <= now) or "ingest" not in row.scopes:
            raise Unauthorized("CI token is invalid, expired or revoked")
        from app.models import Organization

        org = db.get(Organization, row.organization_id)
        if org is None or not org.is_active:
            raise Unauthorized("This organization has been suspended")
        if row.last_used_at is None or now - row.last_used_at > timedelta(seconds=30):
            row.last_used_at, row.last_used_ip = now, None if get_settings().demo_mode else client_ip(request)
        return CiCaller(row.id, row.organization_id, row.name)


class TokenIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    expires_in_days: int | None = Field(default=365, ge=1, le=730)


def _token_out(t: ApiToken) -> dict:
    return {"id": t.id, "name": t.name, "prefix": t.prefix, "scopes": t.scopes, "created_at": t.created_at, "expires_at": t.expires_at,
            "last_used_at": t.last_used_at, "last_used_ip": t.last_used_ip, "revoked_at": t.revoked_at,
            "active": t.revoked_at is None and (t.expires_at is None or t.expires_at > utcnow())}


@router.get("/ci/tokens")
def list_tokens(db: Db, _: Principal = require("integrations:manage")) -> list[dict]:
    return [_token_out(t) for t in db.execute(select(ApiToken).order_by(ApiToken.created_at.desc())).scalars()]


@router.post("/ci/tokens", status_code=201)
def create_token(body: TokenIn, db: Db, principal: Principal = require("integrations:manage")) -> dict:
    raw = TOKEN_PREFIX + new_token(30)
    now = utcnow()
    token = ApiToken(organization_id=principal.organization_id, name=body.name, token_hash=hash_token(raw), prefix=raw[:16],
                     scopes=["ingest"], created_by_user_id=principal.user_id, created_at=now,
                     expires_at=now + timedelta(days=body.expires_in_days) if body.expires_in_days else None)
    db.add(token)
    db.flush()
    audit_event(db, principal, "ci.token_created", entity_type="api_token", entity_id=token.id, data={"name": body.name})
    return {**_token_out(token), "token": raw}  # the only time the secret is returned


@router.delete("/ci/tokens/{token_id}", status_code=204)
def revoke_token(token_id: uuid.UUID, db: Db, principal: Principal = require("integrations:manage")) -> None:
    token = db.get(ApiToken, token_id)
    if token is None:
        raise NotFound("Token not found")
    token.revoked_at = token.revoked_at or utcnow()
    audit_event(db, principal, "ci.token_revoked", entity_type="api_token", entity_id=token.id, data={"name": token.name})


def _process(organization_id: uuid.UUID, job_id: uuid.UUID) -> bool:
    """Run the import job in this request when no worker has taken it. Returns False if a worker has it."""
    job = claim("ci-ingest", job_id)
    if job is None:
        return False
    execute(job)
    return True


def _result(organization_id: uuid.UUID, assessment_id: uuid.UUID) -> dict:
    with tenant_session(organization_id) as db:
        assessment = db.get(Assessment, assessment_id)
        run = db.execute(select(AssessmentRun).where(AssessmentRun.assessment_id == assessment_id)
                         .order_by(AssessmentRun.created_at.desc()).limit(1)).scalar_one_or_none()
        return service.upload_view(assessment, run, get_settings().public_base_url)


@router.post("/ci/ingest")
async def ingest(
    request: Request, response: Response, caller: CiCaller = Depends(ci_caller),
    format: str = Query(..., description="Report format: " + ", ".join(service.formats())),
    target: str | None = Query(None, max_length=1024, description="What was scanned (repository, image reference, URL) when the report does not say"),
    repository: str | None = Query(None, max_length=400), branch: str | None = Query(None, max_length=200),
    commit: str | None = Query(None, max_length=80), pipeline_url: str | None = Query(None, max_length=1000),
    provider: str | None = Query(None, max_length=40, description="github_actions, gitlab_ci, jenkins, azure_pipelines, ..."),
    fail_on: service.GateThreshold = Query("none", description="Fail the gate if an open finding of this severity or higher is present"),
    wait: bool = Query(True, description="Process before responding (up to wait_seconds)"),
    wait_seconds: int = Query(120, ge=5, le=600),
    exit_code: bool = Query(False, description="Respond 412 when the gate fails, so `curl --fail-with-body` fails the build"),
) -> dict:
    """Upload a scanner report from a pipeline. Send the report as the raw request body, or as a
    multipart field named `file`."""
    limit = get_settings().max_upload_bytes
    content_type = request.headers.get("content-type", "")
    if content_type.startswith("multipart/form-data"):
        form = await request.form()
        upload = form.get("file")
        if upload is None or isinstance(upload, str):
            raise ValidationFailed("Multipart uploads must include a file field named 'file'")
        data, filename = await upload.read(limit + 1), upload.filename or ""
    else:
        data, filename = await request.body(), ""
    if len(data) > limit:
        raise ValidationFailed(f"Report exceeds the {limit // (1024 * 1024)} MB limit")
    ci = service.CiContext(provider=provider, repository=repository, branch=branch, commit=commit, pipeline_url=pipeline_url,
                           token_name=caller.name)

    def create() -> tuple[uuid.UUID, uuid.UUID]:
        with tenant_session(caller.organization_id) as db:
            assessment = service.create_import(db, organization_id=caller.organization_id, fmt=format, data=data, filename=filename,
                                               target=target, fail_on=fail_on, ci=ci)
            run = start_run(db, assessment, None)
            audit.record(db, organization_id=caller.organization_id, action="ci.ingest", actor_email=f"ci-token:{caller.name}",
                         entity_type="assessment", entity_id=assessment.id,
                         data={"format": format, "repository": repository, "branch": branch, "commit": commit, "size": len(data)})
            return assessment.id, run.job_id

    assessment_id, job_id = await run_in_threadpool(create)
    if wait and not await run_in_threadpool(_process, caller.organization_id, job_id):
        deadline = asyncio.get_running_loop().time() + wait_seconds
        while asyncio.get_running_loop().time() < deadline:  # a worker took the job; wait for it
            result = await run_in_threadpool(_result, caller.organization_id, assessment_id)
            if result["status"] not in ("queued", "running"):
                break
            await asyncio.sleep(1)
    result = await run_in_threadpool(_result, caller.organization_id, assessment_id)
    if result["status"] in ("queued", "running"):
        response.status_code = 202
    elif exit_code and result["status"] == "failed":
        response.status_code = 422
    elif exit_code and result["gate"] and not result["gate"]["passed"]:
        response.status_code = 412
    return result


@router.get("/ci/uploads/{assessment_id}")
def upload_status(assessment_id: uuid.UUID, caller: CiCaller = Depends(ci_caller)) -> dict:
    """Result of an upload, for pipelines that used wait=false."""
    with tenant_session(caller.organization_id) as db:
        assessment = db.get(Assessment, assessment_id)
        if assessment is None or assessment.kind != "scanner_import" or (assessment.config or {}).get("ci", {}).get("token_name") is None:
            raise NotFound("Upload not found")
    return _result(caller.organization_id, assessment_id)


@router.get("/imports")
def list_imports(db: Db, paging: Paging, _: Principal = require("assessments:read"),
                 source: Literal["all", "ci", "manual"] = "all", format: list[str] | None = Query(None)) -> dict:
    """History of scanner report uploads from users and pipelines."""
    stmt = select(Assessment).where(Assessment.kind == "scanner_import").order_by(Assessment.created_at.desc())
    if source == "ci":  # ->> yields SQL NULL for both a missing key and a JSON null
        stmt = stmt.where(Assessment.config["ci"].astext.isnot(None))
    elif source == "manual":
        stmt = stmt.where(Assessment.config["ci"].astext.is_(None))
    if format:
        stmt = stmt.where(Assessment.config["format"].astext.in_(format))
    rows, total = paginate(db, stmt, paging)
    runs = {r.assessment_id: r for r in db.execute(select(AssessmentRun).where(AssessmentRun.assessment_id.in_([a.id for a in rows]))).scalars()} if rows else {}
    base = get_settings().public_base_url
    return {"items": [service.upload_view(a, runs.get(a.id), base) for a in rows], "total": total, "page": paging.page,
            "page_size": paging.page_size, "formats": service.formats()}
