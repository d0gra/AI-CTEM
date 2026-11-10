"""Assessment run bookkeeping shared by the queue and the engines."""

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models import Assessment, AssessmentRun


def mark_run_for_job(db: Session, job_id: uuid.UUID, status: str, error: str | None = None) -> None:
    run = db.execute(select(AssessmentRun).where(AssessmentRun.job_id == job_id)).scalar_one_or_none()
    if run is None or run.status in ("succeeded", "failed", "cancelled"):
        return
    run.status, run.error, run.finished_at = status, (error or "")[:4000] or None, utcnow()
    if status == "failed":
        from app.domains.notifications.service import notify

        assessment = db.get(Assessment, run.assessment_id)
        notify(db, organization_id=run.organization_id, event_type="assessment.failed", severity="medium",
               title=f"Assessment failed: {assessment.name if assessment else run.assessment_id}",
               body=(error or "")[:500], entity_type="assessment_run", entity_id=run.id)
