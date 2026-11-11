"""Worker process: executes queued jobs and runs the scheduler.

    python -m app.workers.runner

Any number of worker processes may run. Job claiming is safe under concurrency (SKIP LOCKED) and
the scheduler tick is serialised across processes with a PostgreSQL advisory lock.
"""

import os
import signal
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from prometheus_client import Counter, Gauge, start_http_server
from sqlalchemy import select, text

import app.api.router  # noqa: F401  (registers every engine and job handler)
from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger
from app.db.base import utcnow
from app.db.session import system_session, tenant_session
from app.workers import queue

log = get_logger("ctem.worker")
JOBS = Counter("ctem_jobs_total", "Jobs finished", ["type", "outcome"])
RUNNING = Gauge("ctem_jobs_running", "Jobs currently executing in this worker")
SCHEDULER_LOCK = 0x4354454D  # "CTEM"

# job type -> minimum interval between runs per organization
PERIODIC: dict[str, timedelta] = {
    "remediation.sla_check": timedelta(hours=1),
    "risk.expire_acceptances": timedelta(hours=1),
    "policies.evaluate": timedelta(hours=24),
    "assets.mark_stale": timedelta(hours=24),
}
INTEL_INTERVAL = timedelta(hours=24)
INTEL_SOURCES = ("cisa_kev", "epss")


def schedule_tick() -> dict:
    """Enqueue due recurring assessments and periodic maintenance. Safe to call from many workers."""
    from app.domains.assessments.service import start_run
    from app.integrations.intel import sources as intel
    from app.models import Assessment, IntelSyncState, Job, Organization

    stats = {"assessments": 0, "periodic": 0, "intel": 0, "reaped": queue.reap_stale()}
    with system_session() as db:
        if not db.execute(text("select pg_try_advisory_xact_lock(:k)"), {"k": SCHEDULER_LOCK}).scalar():
            return stats  # another worker is scheduling
        now = utcnow()
        due = list(db.execute(select(Assessment.id, Assessment.organization_id).where(
            Assessment.enabled, Assessment.next_run_at.isnot(None), Assessment.next_run_at <= now)).all())
        org_ids = list(db.execute(select(Organization.id).where(Organization.is_active)).scalars())
        for job_type, interval in PERIODIC.items():
            recent = set(db.execute(select(Job.organization_id).where(Job.type == job_type, Job.created_at > now - interval)).scalars())
            for org_id in org_ids:
                if org_id not in recent:
                    queue.enqueue(db, organization_id=org_id, job_type=job_type, idempotency_key=f"periodic:{job_type}")
                    stats["periodic"] += 1
        # Global threat-intel refresh, followed by rescoring for every organization.
        states = {s.source: s for s in db.execute(select(IntelSyncState)).scalars()}
        stale = [s for s in INTEL_SOURCES if not (states.get(s) and states[s].last_attempt_at and states[s].last_attempt_at > now - INTEL_INTERVAL)]
        for source in stale:
            try:
                intel.run_sync(db, source)
                stats["intel"] += 1
            except Exception as exc:  # recorded in intel_sync_state by run_sync; retried next interval
                log.warning("intel_sync_failed", source=source, error=str(exc)[:300])
        if stats["intel"]:
            for org_id in org_ids:
                queue.enqueue(db, organization_id=org_id, job_type="risk.recalculate", idempotency_key="risk.recalculate")
    for assessment_id, org_id in due:
        with tenant_session(org_id) as db:
            assessment = db.get(Assessment, assessment_id)
            if assessment is None:
                continue
            try:
                start_run(db, assessment, None)
                stats["assessments"] += 1
            except Exception as exc:  # e.g. a run is already in progress, or AI authorization expired
                log.info("scheduled_run_skipped", assessment_id=str(assessment_id), reason=str(exc)[:200])
            assessment.next_run_at = utcnow() + timedelta(minutes=assessment.schedule_interval_minutes or 60)
    return stats


def _execute(job) -> None:
    RUNNING.inc()
    try:
        outcome = queue.execute(job)
        JOBS.labels(job.type, outcome).inc()
        log.info("job_finished", job_id=str(job.id), type=job.type, outcome=outcome, organization_id=str(job.organization_id))
    finally:
        RUNNING.dec()


def main() -> None:
    configure_logging()
    settings = get_settings()
    worker_id = f"{socket.gethostname()}:{os.getpid()}"
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    metrics_port = int(os.environ.get("CTEM_WORKER_METRICS_PORT", "0"))
    if metrics_port:
        start_http_server(metrics_port)
    log.info("worker_started", worker_id=worker_id, concurrency=settings.worker_concurrency, job_types=queue.registered_job_types())
    pool = ThreadPoolExecutor(max_workers=settings.worker_concurrency, thread_name_prefix="job")
    slots = threading.Semaphore(settings.worker_concurrency)
    last_tick = 0.0
    while not stop.is_set():
        if time.monotonic() - last_tick > 30:
            last_tick = time.monotonic()
            try:
                stats = schedule_tick()
                if any(stats.values()):
                    log.info("scheduler_tick", **stats)
            except Exception:
                log.error("scheduler_tick_failed", exc_info=True)
        if not slots.acquire(timeout=settings.worker_poll_seconds):
            continue
        try:
            job = queue.claim(worker_id)
        except Exception:
            log.error("job_claim_failed", exc_info=True)
            job = None
        if job is None:
            slots.release()
            stop.wait(settings.worker_poll_seconds)
            continue
        log.info("job_started", job_id=str(job.id), type=job.type, attempt=job.attempts, organization_id=str(job.organization_id))
        future = pool.submit(_execute, job)
        future.add_done_callback(lambda _f: slots.release())
    log.info("worker_stopping", worker_id=worker_id)
    pool.shutdown(wait=True)  # running jobs finish; anything interrupted is requeued by the stale-job reaper


if __name__ == "__main__":
    main()
