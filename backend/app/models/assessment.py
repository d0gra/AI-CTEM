"""Assessment definitions, runs and the background job queue."""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, IdMixin, TenantMixin, TimestampMixin, fk

JOB_STATES = ("queued", "running", "succeeded", "failed", "cancelled", "dead")


class Job(Base, IdMixin, TenantMixin, TimestampMixin):
    """Durable background job. Workers claim rows with FOR UPDATE SKIP LOCKED."""

    __tablename__ = "jobs"
    __table_args__ = (
        Index("ix_jobs_claim", "state", "run_after"),
        # Idempotency: at most one non-terminal job per (organization, idempotency_key).
        Index(
            "uq_jobs_active_idempotency", "organization_id", "idempotency_key", unique=True,
            postgresql_where=text("idempotency_key IS NOT NULL AND state IN ('queued', 'running')"),
        ),
    )

    type: Mapped[str] = mapped_column(String(64))
    config: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    state: Mapped[str] = mapped_column(String(16), default="queued", server_default="queued")
    progress: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    progress_message: Mapped[str] = mapped_column(String(300), default="", server_default="")
    result: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    error: Mapped[str | None] = mapped_column(Text)
    error_class: Mapped[str | None] = mapped_column(String(32))  # transient | permanent | cancelled
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    max_attempts: Mapped[int] = mapped_column(Integer, default=3, server_default="3")
    run_after: Mapped[datetime]
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]
    heartbeat_at: Mapped[datetime | None]
    locked_by: Mapped[str | None] = mapped_column(String(120))
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    idempotency_key: Mapped[str | None] = mapped_column(String(200))
    created_by_user_id: Mapped[uuid.UUID | None] = fk("users.id", ondelete="SET NULL", nullable=True, index=False)


class Assessment(Base, IdMixin, TenantMixin, TimestampMixin):
    __tablename__ = "assessments"

    name: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(48))  # key in the assessment registry
    config: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    integration_id: Mapped[uuid.UUID | None] = fk("integrations.id", ondelete="SET NULL", nullable=True)
    schedule_interval_minutes: Mapped[int | None] = mapped_column(Integer)
    next_run_at: Mapped[datetime | None] = mapped_column(index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    created_by_user_id: Mapped[uuid.UUID | None] = fk("users.id", ondelete="SET NULL", nullable=True, index=False)


class AssessmentTarget(Base, IdMixin, TenantMixin):
    __tablename__ = "assessment_targets"

    assessment_id: Mapped[uuid.UUID] = fk("assessments.id")
    kind: Mapped[str] = mapped_column(String(24))  # domain | url | cidr | path
    value: Mapped[str] = mapped_column(String(1024))


class AssessmentRun(Base, IdMixin, TenantMixin, TimestampMixin):
    __tablename__ = "assessment_runs"
    __table_args__ = (Index("ix_runs_assessment_time", "assessment_id", "created_at"),)

    assessment_id: Mapped[uuid.UUID] = fk("assessments.id", index=False)
    job_id: Mapped[uuid.UUID | None] = fk("jobs.id", ondelete="SET NULL", nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="queued", server_default="queued")
    dry_run: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    retest_of_finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL", use_alter=True, name="fk_assessment_runs_retest_finding")
    )
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]
    summary: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    error: Mapped[str | None] = mapped_column(Text)
    triggered_by_user_id: Mapped[uuid.UUID | None] = fk("users.id", ondelete="SET NULL", nullable=True, index=False)
