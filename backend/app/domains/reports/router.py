import uuid
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Response
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select

from app.api.deps import Db, Paging, Principal, audit_event, paginate, require
from app.core import storage
from app.core.errors import Conflict, NotFound
from app.core.security import sha256_hex
from app.db.base import utcnow
from app.domains.reports import builder
from app.models import Report
from app.workers.queue import JobContext, PermanentJobError, enqueue, job_handler

router = APIRouter(prefix="/reports", tags=["Reports"])


@job_handler("reports.generate")
def generate_job(job: JobContext, db) -> dict:
    report = db.get(Report, uuid.UUID(job.config["report_id"]))
    if report is None:
        raise PermanentJobError("Report no longer exists")
    report.status = "running"
    db.commit()
    params = report.params or {}
    data = builder.build(db, job.organization_id, report.type,
                         datetime.fromisoformat(params["date_from"]) if params.get("date_from") else None,
                         datetime.fromisoformat(params["date_to"]) if params.get("date_to") else None)
    if report.title:
        data.title = report.title
    content = builder.RENDERERS[report.format](data)
    key = storage.new_key(job.organization_id, "reports", f".{report.format}")
    storage.get_storage().put(key, content, builder.FORMATS[report.format])
    report.storage_key, report.size_bytes, report.sha256 = key, len(content), sha256_hex(content)
    report.status, report.generated_at, report.error = "ready", utcnow(), None
    return {"report_id": str(report.id), "size_bytes": len(content), "rows": sum(len(s.rows) for s in data.sections)}


class ReportIn(BaseModel):
    type: Literal[tuple(builder.REPORT_TYPES)]  # type: ignore[valid-type]
    format: Literal["pdf", "csv", "json", "xlsx"]
    title: str | None = Field(default=None, max_length=300)
    date_from: datetime | None = None
    date_to: datetime | None = None

    @model_validator(mode="after")
    def _range(self) -> "ReportIn":
        if self.date_from and self.date_to and self.date_from > self.date_to:
            raise ValueError("date_from must not be after date_to")
        return self


def _out(r: Report) -> dict:
    return {"id": r.id, "type": r.type, "format": r.format, "title": r.title, "params": r.params, "status": r.status, "error": r.error,
            "size_bytes": r.size_bytes, "sha256": r.sha256, "generated_at": r.generated_at, "created_at": r.created_at, "job_id": r.job_id}


@router.get("/types")
def report_types(_: Principal = require("reports:read")) -> dict:
    return {"types": builder.REPORT_TYPES, "formats": sorted(builder.FORMATS)}


@router.get("")
def list_reports(db: Db, paging: Paging, _: Principal = require("reports:read")) -> dict:
    rows, total = paginate(db, select(Report).order_by(Report.created_at.desc()), paging)
    return {"items": [_out(r) for r in rows], "total": total, "page": paging.page, "page_size": paging.page_size}


@router.post("", status_code=202)
def create_report(body: ReportIn, db: Db, principal: Principal = require("reports:generate")) -> dict:
    report = Report(organization_id=principal.organization_id, type=body.type, format=body.format,
                    title=body.title or builder.REPORT_TYPES[body.type], requested_by_user_id=principal.user_id,
                    params={"date_from": body.date_from.isoformat() if body.date_from else None,
                            "date_to": body.date_to.isoformat() if body.date_to else None})
    db.add(report)
    db.flush()
    job = enqueue(db, organization_id=principal.organization_id, job_type="reports.generate", config={"report_id": str(report.id)},
                  created_by_user_id=principal.user_id, max_attempts=2)
    report.job_id = job.id
    audit_event(db, principal, "report.requested", entity_type="report", entity_id=report.id, data={"type": body.type, "format": body.format})
    return _out(report)


@router.get("/{report_id}")
def get_report(report_id: uuid.UUID, db: Db, _: Principal = require("reports:read")) -> dict:
    report = db.get(Report, report_id)
    if report is None:
        raise NotFound("Report not found")
    return _out(report)


@router.get("/{report_id}/download")
def download_report(report_id: uuid.UUID, db: Db, principal: Principal = require("reports:read")) -> Response:
    report = db.get(Report, report_id)
    if report is None:
        raise NotFound("Report not found")
    if report.status != "ready" or not report.storage_key:
        raise Conflict(f"Report is {report.status}")
    content = storage.read_for_org(principal.organization_id, report.storage_key)
    audit_event(db, principal, "report.downloaded", entity_type="report", entity_id=report.id, data={"sha256": report.sha256})
    filename = f"{report.type}-{report.generated_at:%Y%m%d-%H%M}.{report.format}"
    return Response(content=content, media_type=builder.FORMATS[report.format],
                    headers={"Content-Disposition": f'attachment; filename="{filename}"', "X-Content-Type-Options": "nosniff"})


@router.delete("/{report_id}", status_code=204)
def delete_report(report_id: uuid.UUID, db: Db, principal: Principal = require("reports:generate")) -> None:
    report = db.get(Report, report_id)
    if report is None:
        raise NotFound("Report not found")
    if report.storage_key:
        storage.get_storage().delete(report.storage_key)
    db.delete(report)
    audit_event(db, principal, "report.deleted", entity_type="report", entity_id=report_id)
