"""Scanner-result ingestion shared by manual uploads and CI/CD pipelines."""

import uuid
from typing import Literal

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import storage
from app.core.config import get_settings
from app.core.errors import ValidationFailed
from app.core.security import sha256_hex
from app.models import Assessment, AssessmentRun, Finding

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
GateThreshold = Literal["none", "low", "medium", "high", "critical"]


class CiContext(BaseModel):
    """Where a pipeline upload came from. All fields are optional and shown in the upload history."""

    provider: str | None = Field(default=None, max_length=40)  # github_actions | gitlab_ci | jenkins | ...
    repository: str | None = Field(default=None, max_length=400)
    branch: str | None = Field(default=None, max_length=200)
    commit: str | None = Field(default=None, max_length=80)
    pipeline_url: str | None = Field(default=None, max_length=1000)
    token_name: str | None = Field(default=None, max_length=120)


def formats() -> list[str]:
    from app.integrations.scanners.parsers import PARSERS

    return sorted(PARSERS)


def create_import(db: Session, *, organization_id: uuid.UUID, fmt: str, data: bytes, filename: str, target: str | None,
                  fail_on: GateThreshold = "none", ci: CiContext | None = None, created_by_user_id: uuid.UUID | None = None) -> Assessment:
    if fmt not in formats():
        raise ValidationFailed(f"Unsupported format {fmt!r}", details={"formats": formats()})
    limit = get_settings().max_upload_bytes
    if len(data) > limit:
        raise ValidationFailed(f"Report exceeds the {limit // (1024 * 1024)} MB limit")
    if not data.strip():
        raise ValidationFailed("Report is empty")
    key = storage.new_key(organization_id, "scanner-imports", ".dat")
    storage.get_storage().put(key, data, "application/octet-stream")
    label = (ci.repository if ci and ci.repository else target) or filename or "upload"
    assessment = Assessment(
        organization_id=organization_id, kind="scanner_import", created_by_user_id=created_by_user_id,
        name=f"{'CI' if ci else 'Upload'} · {fmt} · {label[-120:]}",
        config={"format": fmt, "storage_key": key, "sha256": sha256_hex(data), "target": target or (ci.repository if ci else None),
                "filename": filename[-200:], "fail_on": fail_on, "ci": ci.model_dump(exclude_none=True) if ci else None},
    )
    db.add(assessment)
    db.flush()
    return assessment


def evaluate_gate(db: Session, run_id: uuid.UUID, threshold: str) -> dict:
    """Open findings observed in this upload at or above the threshold severity block the build."""
    from app.models.finding import OPEN_STATUSES

    rows = list(db.execute(select(Finding).where(Finding.assessment_run_id == run_id)).scalars())
    by_severity: dict[str, int] = {}
    for f in rows:
        if f.status in OPEN_STATUSES:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    suppressed = sum(1 for f in rows if f.status in ("accepted_risk", "false_positive"))
    blocking = [] if threshold == "none" else sorted(
        (f for f in rows if f.status in OPEN_STATUSES and SEVERITY_RANK[f.severity] >= SEVERITY_RANK[threshold]),
        key=lambda f: (-SEVERITY_RANK[f.severity], -f.risk_score))
    return {"threshold": threshold, "passed": not blocking, "blocking_count": len(blocking),
            "blocking": [{"id": str(f.id), "title": f.title, "severity": f.severity, "risk_score": f.risk_score} for f in blocking[:20]],
            "open_by_severity": by_severity, "suppressed": suppressed}


def upload_view(assessment: Assessment, run: AssessmentRun | None, base_url: str) -> dict:
    summary = (run.summary if run else None) or {}
    config = assessment.config or {}
    return {
        "id": assessment.id, "run_id": run.id if run else None, "format": config.get("format"), "filename": config.get("filename"),
        "target": config.get("target"), "ci": config.get("ci"), "fail_on": config.get("fail_on", "none"),
        "status": run.status if run else "queued", "error": run.error if run else None,
        "created_at": assessment.created_at, "finished_at": run.finished_at if run else None,
        "findings_new": summary.get("findings_created"), "findings_seen": summary.get("findings_seen"),
        "gate": summary.get("gate"), "url": f"{base_url}/findings?source=import:{config.get('format')}",
    }
