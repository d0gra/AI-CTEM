import uuid
from datetime import timedelta

from fastapi import APIRouter, File, Form, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.deps import Db, Page, Paging, Principal, audit_event, paginate, require
from app.core import storage
from app.core.config import get_settings
from app.core.errors import NotFound, ValidationFailed
from app.core.security import sha256_hex
from app.db.base import utcnow
from app.domains.assessments import service
from app.models import Assessment, AssessmentRun, AssessmentTarget, Asset, Job
from app.workers.queue import request_cancel

router = APIRouter(tags=["Assessments"])


class TargetIn(BaseModel):
    kind: str
    value: str = Field(max_length=1024)


class AssessmentIn(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    kind: str
    config: dict = {}
    targets: list[TargetIn] = []
    integration_id: uuid.UUID | None = None
    schedule_interval_minutes: int | None = Field(default=None, ge=15, le=60 * 24 * 30)


class AssessmentPatch(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=200)
    enabled: bool | None = None
    schedule_interval_minutes: int | None = Field(default=None, ge=15, le=60 * 24 * 30)


class RunIn(BaseModel):
    dry_run: bool = False


def _run_out(r: AssessmentRun) -> dict:
    return {"id": r.id, "assessment_id": r.assessment_id, "job_id": r.job_id, "status": r.status, "dry_run": r.dry_run,
            "started_at": r.started_at, "finished_at": r.finished_at, "summary": r.summary, "error": r.error,
            "created_at": r.created_at, "retest_of_finding_id": r.retest_of_finding_id}


def _out(db: Db, a: Assessment) -> dict:
    targets = db.execute(select(AssessmentTarget).where(AssessmentTarget.assessment_id == a.id)).scalars()
    last = db.execute(select(AssessmentRun).where(AssessmentRun.assessment_id == a.id)
                      .order_by(AssessmentRun.created_at.desc()).limit(1)).scalar_one_or_none()
    spec = service.ENGINES.get(a.kind)
    return {"id": a.id, "name": a.name, "kind": a.kind, "module": spec.module if spec else None,
            "active": spec.active if spec else None, "config": a.config, "integration_id": a.integration_id,
            "schedule_interval_minutes": a.schedule_interval_minutes, "next_run_at": a.next_run_at,
            "enabled": a.enabled, "created_at": a.created_at,
            "targets": [{"kind": t.kind, "value": t.value, "asset_id": t.asset_id} for t in targets],
            "last_run": _run_out(last) if last else None}


def _get(db: Db, assessment_id: uuid.UUID) -> Assessment:
    a = db.get(Assessment, assessment_id)
    if a is None:
        raise NotFound("Assessment not found")
    return a


def _permission_for(kind: str) -> str:
    return "ai_redteam:run" if kind == "ai_redteam" else "assessments:run"


@router.get("/assessments/engines")
def list_engines(_: Principal = require("assessments:read")) -> list[dict]:
    return [{"kind": s.kind, "name": s.name, "description": s.description, "module": s.module, "active": s.active,
             "target_kinds": list(s.target_kinds), "requires_connector": s.requires_connector,
             "tool": service.tool_status(s), "config_schema": s.config_model.model_json_schema()}
            for s in sorted(service.ENGINES.values(), key=lambda s: (s.module, s.name))]


@router.get("/assessments")
def list_assessments(db: Db, paging: Paging, _: Principal = require("assessments:read"),
                     module: str | None = None, kind: str | None = None) -> dict:
    stmt = select(Assessment).order_by(Assessment.created_at.desc())
    kinds = [k for k, s in service.ENGINES.items() if s.module == module] if module else None
    if kinds is not None:
        stmt = stmt.where(Assessment.kind.in_(kinds))
    if kind:
        stmt = stmt.where(Assessment.kind == kind)
    rows, total = paginate(db, stmt, paging)
    return {"items": [_out(db, a) for a in rows], "total": total, "page": paging.page, "page_size": paging.page_size}


@router.post("/assessments", status_code=201)
def create_assessment(body: AssessmentIn, db: Db, principal: Principal = require("assessments:run")) -> dict:
    if body.kind == "ai_redteam":
        raise ValidationFailed("AI red team assessments are created through /ai-redteam/assessments")
    spec, config, targets = service.validate_definition(
        db, body.kind, body.config, [t.model_dump() for t in body.targets], body.integration_id)
    a = Assessment(organization_id=principal.organization_id, name=body.name, kind=body.kind,
                   config=config.model_dump(mode="json"), integration_id=body.integration_id,
                   schedule_interval_minutes=body.schedule_interval_minutes, created_by_user_id=principal.user_id,
                   next_run_at=utcnow() + timedelta(minutes=body.schedule_interval_minutes)
                   if body.schedule_interval_minutes else None)
    db.add(a)
    db.flush()
    for t in targets:
        asset_id = None
        if t["kind"] == "asset":
            asset = db.get(Asset, uuid.UUID(t["value"])) if _is_uuid(t["value"]) else None
            if asset is None:
                raise ValidationFailed("Target asset does not exist")
            asset_id = asset.id
        db.add(AssessmentTarget(organization_id=a.organization_id, assessment_id=a.id, kind=t["kind"],
                                value=t["value"], asset_id=asset_id))
    db.flush()
    audit_event(db, principal, "assessment.created", entity_type="assessment", entity_id=a.id,
                data={"kind": a.kind, "active": spec.active, "targets": [t["value"] for t in targets]})
    return _out(db, a)


def _is_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
        return True
    except ValueError:
        return False


@router.get("/assessments/{assessment_id}")
def get_assessment(assessment_id: uuid.UUID, db: Db, _: Principal = require("assessments:read")) -> dict:
    return _out(db, _get(db, assessment_id))


@router.patch("/assessments/{assessment_id}")
def update_assessment(assessment_id: uuid.UUID, body: AssessmentPatch, db: Db,
                      principal: Principal = require("assessments:run")) -> dict:
    a = _get(db, assessment_id)
    if body.name:
        a.name = body.name
    if body.enabled is not None:
        a.enabled = body.enabled
    if "schedule_interval_minutes" in body.model_fields_set:
        a.schedule_interval_minutes = body.schedule_interval_minutes
        a.next_run_at = (utcnow() + timedelta(minutes=body.schedule_interval_minutes)
                         if body.schedule_interval_minutes else None)
    audit_event(db, principal, "assessment.updated", entity_type="assessment", entity_id=a.id,
                data=body.model_dump(exclude_unset=True))
    return _out(db, a)


@router.delete("/assessments/{assessment_id}", status_code=204)
def delete_assessment(assessment_id: uuid.UUID, db: Db, principal: Principal = require("assessments:run")) -> None:
    a = _get(db, assessment_id)
    db.delete(a)
    audit_event(db, principal, "assessment.deleted", entity_type="assessment", entity_id=assessment_id)


@router.post("/assessments/{assessment_id}/run", status_code=202)
def run_assessment(assessment_id: uuid.UUID, body: RunIn, db: Db, principal: Principal = require("assessments:read")) -> dict:
    a = _get(db, assessment_id)
    needed = _permission_for(a.kind)
    if not principal.has(needed):
        from app.core.errors import Forbidden

        raise Forbidden("You do not have permission to run this assessment", details={"missing": [needed]})
    if a.kind == "ai_redteam":
        from app.engines.ai_redteam.runner import assert_authorization_current

        assert_authorization_current(db, a)
    return _run_out(service.start_run(db, a, principal, dry_run=body.dry_run))


@router.get("/assessment-runs")
def list_runs(db: Db, paging: Paging, _: Principal = require("assessments:read"),
              assessment_id: uuid.UUID | None = None) -> dict:
    stmt = select(AssessmentRun).order_by(AssessmentRun.created_at.desc())
    if assessment_id:
        stmt = stmt.where(AssessmentRun.assessment_id == assessment_id)
    rows, total = paginate(db, stmt, paging)
    return {"items": [_run_out(r) for r in rows], "total": total, "page": paging.page, "page_size": paging.page_size}


@router.get("/assessment-runs/{run_id}")
def get_run(run_id: uuid.UUID, db: Db, _: Principal = require("assessments:read")) -> dict:
    run = db.get(AssessmentRun, run_id)
    if run is None:
        raise NotFound("Run not found")
    job = db.get(Job, run.job_id) if run.job_id else None
    return {**_run_out(run), "job": _job_out(job) if job else None}


def _job_out(j: Job) -> dict:
    return {"id": j.id, "type": j.type, "state": j.state, "progress": j.progress,
            "progress_message": j.progress_message, "attempts": j.attempts, "max_attempts": j.max_attempts,
            "error": j.error, "error_class": j.error_class, "result": j.result, "created_at": j.created_at,
            "started_at": j.started_at, "finished_at": j.finished_at, "cancel_requested": j.cancel_requested}


@router.get("/jobs")
def list_jobs(db: Db, paging: Paging, _: Principal = require("assessments:read"), state: str | None = None,
              type: str | None = None) -> dict:
    stmt = select(Job).order_by(Job.created_at.desc())
    if state:
        stmt = stmt.where(Job.state == state)
    if type:
        stmt = stmt.where(Job.type == type)
    rows, total = paginate(db, stmt, paging)
    return {"items": [_job_out(j) for j in rows], "total": total, "page": paging.page, "page_size": paging.page_size}


@router.get("/jobs/{job_id}")
def get_job(job_id: uuid.UUID, db: Db, _: Principal = require("assessments:read")) -> dict:
    job = db.get(Job, job_id)
    if job is None:
        raise NotFound("Job not found")
    return _job_out(job)


@router.post("/jobs/{job_id}/cancel", status_code=202)
def cancel_job(job_id: uuid.UUID, db: Db, principal: Principal = require("assessments:run")) -> dict:
    job = db.get(Job, job_id)
    if job is None:
        raise NotFound("Job not found")
    request_cancel(db, job)
    if job.state == "cancelled":
        from app.domains.assessments.runs import mark_run_for_job

        mark_run_for_job(db, job.id, "cancelled", "Cancelled before start")
    audit_event(db, principal, "job.cancel_requested", entity_type="job", entity_id=job.id)
    return _job_out(job)


@router.post("/scanner-imports", status_code=202)
async def import_scanner_results(
    db: Db, principal: Principal = require("assessments:run"),
    format: str = Form(...), file: UploadFile = File(...),
    target: str | None = Form(None, max_length=1024, description="Asset identifier when the report does not name its target"),
) -> dict:
    """Ingest a results file produced by a supported scanner. Parsing happens in a worker."""
    from app.integrations.scanners.parsers import PARSERS

    if format not in PARSERS:
        raise ValidationFailed(f"Unsupported format {format!r}", details={"formats": sorted(PARSERS)})
    limit = get_settings().max_upload_bytes
    data = await file.read(limit + 1)
    if len(data) > limit:
        raise ValidationFailed(f"File exceeds the {limit // (1024 * 1024)} MB limit")
    if not data.strip():
        raise ValidationFailed("File is empty")
    key = storage.new_key(principal.organization_id, "scanner-imports", ".dat")
    storage.get_storage().put(key, data, "application/octet-stream")
    a = Assessment(organization_id=principal.organization_id, kind="scanner_import",
                   name=f"Import: {format} ({(file.filename or 'upload')[-80:]})",
                   config={"format": format, "storage_key": key, "sha256": sha256_hex(data), "target": target,
                           "filename": (file.filename or "")[-200:]},
                   created_by_user_id=principal.user_id)
    db.add(a)
    db.flush()
    audit_event(db, principal, "scanner.import", entity_type="assessment", entity_id=a.id,
                data={"format": format, "sha256": a.config["sha256"], "size": len(data)})
    return _run_out(service.start_run(db, a, principal))
