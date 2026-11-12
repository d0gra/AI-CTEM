"""Continuous AI posture evaluation.

Whenever an AI asset is created or its posture attributes change, and after any assessment that
touched AI assets, the organization's standing "AI posture review" assessment is run so findings
reflect the current configuration without anyone having to start it.
"""

import uuid
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models import Assessment, AssessmentRun
from app.workers.queue import JobContext, enqueue, job_handler

NAME = "Continuous AI posture review"


def _standing_assessment(db: Session, organization_id: uuid.UUID) -> Assessment:
    assessment = db.execute(select(Assessment).where(Assessment.kind == "ai_posture_review", Assessment.name == NAME)).scalars().first()
    if assessment is None:
        assessment = Assessment(organization_id=organization_id, kind="ai_posture_review", name=NAME, config={},
                                schedule_interval_minutes=24 * 60, next_run_at=utcnow() + timedelta(days=1))
        db.add(assessment)
        db.flush()
    return assessment


def request_review(db: Session, organization_id: uuid.UUID) -> None:
    from app.domains.assessments.service import start_run

    assessment = _standing_assessment(db, organization_id)
    active = db.execute(select(AssessmentRun.status).where(AssessmentRun.assessment_id == assessment.id,
                                                           AssessmentRun.status.in_(("queued", "running")))).scalars().first()
    if active == "queued":
        return  # the queued run will read the latest configuration
    if active == "running":  # re-run once the current pass has finished
        enqueue(db, organization_id=organization_id, job_type="ai.posture_rerun", idempotency_key="ai.posture_rerun",
                run_after=utcnow() + timedelta(seconds=20))
        return
    start_run(db, assessment, None)


@job_handler("ai.posture_rerun")
def rerun_job(job: JobContext, db: Session) -> dict:
    request_review(db, job.organization_id)
    return {"requested": True}
