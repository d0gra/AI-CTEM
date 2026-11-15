"""Data retention: a daily job per organization that removes operational records past their retention period.

What is removed is the by-product of running the platform, not the security record. Assets, findings,
their evidence and history, risk decisions and policies are never touched, and the audit log is
append-only for the application role and is kept for the life of the organization.

Each period is a setting in days; 0 keeps that kind of record forever.
"""

from datetime import datetime, timedelta

from sqlalchemy import delete, or_, select

from app.core import storage
from app.core.config import get_settings
from app.core.logging import get_logger
from app.db.base import utcnow
from app.domains.audit import service as audit
from app.models import (
    Assessment,
    AssetDiscoveryEvent,
    Job,
    Notification,
    NotificationDelivery,
    NotificationRead,
    Report,
    UserSession,
    UserToken,
)
from app.workers.queue import JobContext, job_handler

log = get_logger("ctem.retention")
FINISHED = ("succeeded", "failed", "dead", "cancelled")
MIN_JOB_DAYS = 2  # the scheduler looks back a day to decide whether a periodic job is due


def _cutoff(days: int, now: datetime) -> datetime | None:
    return now - timedelta(days=days) if days > 0 else None


def _drop_object(key: str) -> None:
    try:
        storage.get_storage().delete(key)
    except Exception as exc:  # noqa: BLE001  (a missing object must not stop the purge; the row is removed either way)
        log.warning("retention_object_delete_failed", key=key, error=str(exc)[:200])


def purge(db, organization_id, now: datetime | None = None) -> dict:
    """Remove this organization's expired operational records. Returns the number removed per kind."""
    s, now = get_settings(), now or utcnow()
    removed: dict[str, int] = {}

    if cutoff := _cutoff(max(s.retention_jobs_days, MIN_JOB_DAYS) if s.retention_jobs_days else 0, now):
        removed["jobs"] = db.execute(delete(Job).where(
            Job.organization_id == organization_id, Job.state.in_(FINISHED), Job.finished_at < cutoff)).rowcount

    if cutoff := _cutoff(s.retention_sessions_days, now):
        removed["sessions"] = db.execute(delete(UserSession).where(
            UserSession.organization_id == organization_id, or_(UserSession.expires_at < cutoff, UserSession.revoked_at < cutoff))).rowcount
        removed["expired_links"] = db.execute(delete(UserToken).where(
            UserToken.organization_id == organization_id, UserToken.expires_at < cutoff)).rowcount

    if cutoff := _cutoff(s.retention_notifications_days, now):
        old = select(Notification.id).where(Notification.organization_id == organization_id, Notification.created_at < cutoff)
        db.execute(delete(NotificationRead).where(NotificationRead.notification_id.in_(old)))
        db.execute(delete(NotificationDelivery).where(NotificationDelivery.notification_id.in_(old)))
        removed["notifications"] = db.execute(delete(Notification).where(
            Notification.organization_id == organization_id, Notification.created_at < cutoff)).rowcount

    if cutoff := _cutoff(s.retention_asset_observations_days, now):
        # Only repeat observations. First discovery, changes, stale marks and manual edits are the asset's history.
        removed["asset_observations"] = db.execute(delete(AssetDiscoveryEvent).where(
            AssetDiscoveryEvent.organization_id == organization_id, AssetDiscoveryEvent.event_type == "observed",
            AssetDiscoveryEvent.occurred_at < cutoff)).rowcount

    if cutoff := _cutoff(s.retention_reports_days, now):
        count = 0
        for report in db.execute(select(Report).where(Report.organization_id == organization_id, Report.created_at < cutoff)).scalars():
            if report.storage_key:
                _drop_object(report.storage_key)
            db.delete(report)
            count += 1
        removed["reports"] = count

    if cutoff := _cutoff(s.retention_uploads_days, now):
        # The findings an upload produced stay; only the stored copy of the scanner's file goes.
        count = 0
        for a in db.execute(select(Assessment).where(Assessment.organization_id == organization_id, Assessment.kind == "scanner_import",
                                                     Assessment.created_at < cutoff)).scalars():
            key = (a.config or {}).get("storage_key")
            if key and not (a.config or {}).get("file_purged_at"):
                _drop_object(key)
                a.config = {**a.config, "file_purged_at": now.isoformat()}
                count += 1
        removed["uploaded_files"] = count

    removed = {k: v for k, v in removed.items() if v}
    if removed:
        audit.record(db, organization_id=organization_id, action="retention.purged", actor_email="system", data=removed)
    return removed


@job_handler("platform.retention")
def retention_job(job: JobContext, db) -> dict:
    return {"removed": purge(db, job.organization_id)}
