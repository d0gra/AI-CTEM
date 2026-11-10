"""Durable PostgreSQL-backed job queue.

Jobs are rows in `jobs`. Workers claim them with FOR UPDATE SKIP LOCKED, so any number of
worker processes can run concurrently without double execution. Properties:

* Idempotency   a partial unique index allows one active job per (organization, key).
* Bounded retry transient failures are retried with exponential backoff up to max_attempts,
                after which the job moves to the `dead` state (dead-letter) for inspection.
* Cancellation  queued jobs are cancelled immediately; running jobs observe `cancel_requested`
                at their next checkpoint.
* Fairness      at most CTEM_MAX_RUNNING_JOBS_PER_ORG jobs run concurrently per organization.
* Recovery      a job whose worker stops heartbeating is requeued (or dead-lettered).
"""

import traceback
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta

from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import AppError
from app.core.logging import get_logger
from app.db.base import utcnow
from app.db.session import system_session, tenant_session
from app.models import Job

log = get_logger(__name__)

Handler = Callable[["JobContext", Session], dict | None]
_HANDLERS: dict[str, Handler] = {}


class JobCancelled(Exception):
    pass


class PermanentJobError(Exception):
    """A failure that retrying cannot fix (bad configuration, out-of-scope target, ...)."""


def job_handler(job_type: str):
    def decorator(fn: Handler) -> Handler:
        _HANDLERS[job_type] = fn
        return fn

    return decorator


def registered_job_types() -> list[str]:
    return sorted(_HANDLERS)


class JobContext:
    def __init__(self, job: Job):
        self.job_id = job.id
        self.organization_id = job.organization_id
        self.type = job.type
        self.config = dict(job.config or {})
        self.created_by_user_id = job.created_by_user_id
        self.attempt = job.attempts
        self._last_beat = utcnow()

    def progress(self, percent: int, message: str = "") -> None:
        """Record progress and heartbeat; raises JobCancelled when cancellation was requested."""
        with system_session() as db:
            job = db.get(Job, self.job_id)
            if job is None:
                raise JobCancelled()
            job.progress = max(0, min(100, percent))
            job.progress_message = message[:300]
            job.heartbeat_at = utcnow()
            cancel = job.cancel_requested
        if cancel:
            raise JobCancelled()

    def checkpoint(self) -> None:
        """Cheap cancellation/heartbeat check for use inside loops."""
        if (utcnow() - self._last_beat).total_seconds() < 2:
            return
        self._last_beat = utcnow()
        with system_session() as db:
            job = db.get(Job, self.job_id)
            if job is None or job.cancel_requested:
                raise JobCancelled()
            job.heartbeat_at = utcnow()


def enqueue(
    db: Session,
    *,
    organization_id: uuid.UUID,
    job_type: str,
    config: dict | None = None,
    idempotency_key: str | None = None,
    run_after: datetime | None = None,
    created_by_user_id: uuid.UUID | None = None,
    max_attempts: int | None = None,
) -> Job:
    """Create a job in the caller's transaction. If an active job with the same idempotency key
    exists it is returned instead of creating a duplicate."""
    if job_type not in _HANDLERS:
        raise ValueError(f"No handler registered for job type {job_type!r}")
    if idempotency_key:
        existing = db.execute(
            select(Job).where(Job.organization_id == organization_id, Job.idempotency_key == idempotency_key,
                              Job.state.in_(("queued", "running")))
        ).scalar_one_or_none()
        if existing:
            return existing
    job = Job(
        organization_id=organization_id, type=job_type, config=config or {}, idempotency_key=idempotency_key,
        run_after=run_after or utcnow(), created_by_user_id=created_by_user_id,
        max_attempts=max_attempts or get_settings().job_max_attempts,
    )
    try:
        with db.begin_nested():
            db.add(job)
            db.flush()
    except IntegrityError:
        # Lost a race against a concurrent enqueue with the same idempotency key.
        return db.execute(
            select(Job).where(Job.organization_id == organization_id, Job.idempotency_key == idempotency_key,
                              Job.state.in_(("queued", "running")))
        ).scalar_one()
    return job


_CLAIM_SQL = text(
    """
    SELECT j.id FROM jobs j
    WHERE j.state = 'queued' AND j.run_after <= now()
      AND (:job_id IS NULL OR j.id = :job_id)
      AND (SELECT count(*) FROM jobs r WHERE r.organization_id = j.organization_id AND r.state = 'running') < :per_org
    ORDER BY j.run_after, j.created_at
    FOR UPDATE OF j SKIP LOCKED
    LIMIT 1
    """
).bindparams()


def claim(worker_id: str, job_id: uuid.UUID | None = None) -> Job | None:
    with system_session() as db:
        row = db.execute(
            text(_CLAIM_SQL.text.replace(":job_id IS NULL", "CAST(:job_id AS uuid) IS NULL")),
            {"job_id": str(job_id) if job_id else None, "per_org": get_settings().max_running_jobs_per_org},
        ).first()
        if row is None:
            return None
        job = db.get(Job, row[0])
        assert job is not None
        if job.cancel_requested:
            job.state, job.finished_at, job.error_class = "cancelled", utcnow(), "cancelled"
            return None
        job.state, job.locked_by = "running", worker_id
        job.attempts += 1
        job.started_at = job.started_at or utcnow()
        job.heartbeat_at = utcnow()
        db.flush()
        db.expunge(job)
        return job


def _finish(job_id: uuid.UUID, **fields) -> None:
    with system_session() as db:
        job = db.get(Job, job_id)
        if job is None:
            return
        for key, value in fields.items():
            setattr(job, key, value)
        job.locked_by = None


def execute(job: Job) -> str:
    """Run a claimed job to completion and persist its terminal (or retry) state."""
    handler = _HANDLERS.get(job.type)
    ctx = JobContext(job)
    now = utcnow
    if handler is None:
        _finish(job.id, state="failed", error=f"No handler for job type {job.type}", error_class="permanent",
                finished_at=now())
        return "failed"
    try:
        with tenant_session(job.organization_id) as db:
            result = handler(ctx, db) or {}
        _finish(job.id, state="succeeded", result=result, progress=100, finished_at=now(), error=None,
                error_class=None)
        return "succeeded"
    except JobCancelled:
        _finish(job.id, state="cancelled", finished_at=now(), error_class="cancelled")
        _on_terminal_failure(job, "cancelled", "Cancelled")
        return "cancelled"
    except (PermanentJobError, AppError, ValueError) as exc:
        message = getattr(exc, "message", None) or str(exc)
        _finish(job.id, state="failed", error=message[:4000], error_class="permanent", finished_at=now())
        _on_terminal_failure(job, "failed", message)
        log.warning("job_failed_permanent", job_id=str(job.id), type=job.type, error=message[:300])
        return "failed"
    except Exception as exc:  # transient: retry with backoff, then dead-letter
        detail = f"{type(exc).__name__}: {exc}"[:2000]
        if job.attempts >= job.max_attempts:
            _finish(job.id, state="dead", error=detail + "\n" + traceback.format_exc()[-1800:],
                    error_class="transient", finished_at=now())
            _on_terminal_failure(job, "dead", detail)
            log.error("job_dead_lettered", job_id=str(job.id), type=job.type, error=detail[:300])
            return "dead"
        backoff = timedelta(seconds=min(900, 15 * 2 ** (job.attempts - 1)))
        _finish(job.id, state="queued", error=detail, error_class="transient", run_after=now() + backoff)
        log.warning("job_retry_scheduled", job_id=str(job.id), type=job.type, attempt=job.attempts, error=detail[:300])
        return "retry"


def _on_terminal_failure(job: Job, state: str, message: str) -> None:
    """Propagate terminal job failure to the entities that track it, and notify."""
    from app.domains.assessments.runs import mark_run_for_job
    from app.domains.notifications.service import notify
    from app.models import Report

    try:
        with tenant_session(job.organization_id) as db:
            mark_run_for_job(db, job.id, "cancelled" if state == "cancelled" else "failed", message)
            report = db.execute(select(Report).where(Report.job_id == job.id)).scalar_one_or_none()
            if report is not None and report.status in ("queued", "running"):
                report.status, report.error = "failed", message[:2000]
            if state != "cancelled":
                notify(db, organization_id=job.organization_id, event_type="job.failed", severity="medium",
                       title=f"Background job failed: {job.type}", body=message[:500], entity_type="job",
                       entity_id=job.id)
    except Exception:
        log.error("job_failure_propagation_failed", job_id=str(job.id), exc_info=True)


def request_cancel(db: Session, job: Job) -> None:
    if job.state == "queued":
        job.state, job.finished_at, job.error_class = "cancelled", utcnow(), "cancelled"
    elif job.state == "running":
        job.cancel_requested = True


def reap_stale(now: datetime | None = None) -> int:
    """Requeue or dead-letter running jobs whose worker stopped heartbeating."""
    now = now or utcnow()
    cutoff = now - timedelta(seconds=get_settings().job_stale_after_seconds)
    reaped = 0
    with system_session() as db:
        stale = db.execute(
            select(Job).where(Job.state == "running", Job.heartbeat_at < cutoff).with_for_update(skip_locked=True)
        ).scalars()
        for job in stale:
            reaped += 1
            if job.attempts >= job.max_attempts:
                job.state, job.finished_at, job.error_class = "dead", now, "transient"
                job.error = "Worker stopped responding; retry limit reached"
            else:
                job.state, job.locked_by, job.error = "queued", None, "Worker stopped responding; requeued"
    return reaped


def run_pending(limit: int = 100, worker_id: str = "inline") -> list[tuple[str, str]]:
    """Run queued jobs in-process until the queue is empty. Used by tests and the CLI."""
    outcomes = []
    for _ in range(limit):
        job = claim(worker_id)
        if job is None:
            break
        outcomes.append((job.type, execute(job)))
    return outcomes
