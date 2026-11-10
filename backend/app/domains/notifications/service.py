"""Notification creation with storm control, and rule-driven delivery."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.db.base import utcnow
from app.models import Integration, Notification, NotificationDelivery, NotificationRule

log = get_logger(__name__)

EVENT_TYPES = {
    "finding.critical": "Critical finding detected",
    "finding.exploited": "Finding affected by a known-exploited vulnerability",
    "asset.discovered": "New asset discovered",
    "asset.exposed": "Asset newly exposed to the internet",
    "ai.risk": "New AI security risk",
    "ai.config_changed": "Dangerous AI configuration change",
    "attack_path.critical": "Critical attack path identified",
    "sla.breached": "Remediation SLA breached",
    "assessment.failed": "Assessment failed",
    "integration.failed": "Integration failure",
    "job.failed": "Background job failed",
    "risk.acceptance_requested": "Risk acceptance requested",
}
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def notify(
    db: Session,
    *,
    organization_id: uuid.UUID,
    event_type: str,
    severity: str,
    title: str,
    body: str = "",
    entity_type: str | None = None,
    entity_id: uuid.UUID | None = None,
    bucket_hours: int = 24,
) -> uuid.UUID | None:
    """Create an in-app notification and schedule external delivery.

    Notifications are de-duplicated per (event type, entity, time bucket): a repeat within the
    bucket increments `occurrences` on the existing row and does not trigger another delivery.
    Returns the notification id when a new notification was created.
    """
    now = utcnow()
    bucket = int(now.timestamp() // (bucket_hours * 3600))
    dedup_key = f"{event_type}:{entity_id or title[:80]}:{bucket}"
    new_id = uuid.uuid4()
    row = db.execute(
        text(
            """
            INSERT INTO notifications (id, organization_id, event_type, severity, title, body, entity_type,
                                       entity_id, dedup_key, occurrences, created_at)
            VALUES (:id, :org, :event_type, :severity, :title, :body, :entity_type, :entity_id, :dedup, 1, :now)
            ON CONFLICT (organization_id, dedup_key) DO UPDATE SET occurrences = notifications.occurrences + 1
            RETURNING id, (xmax = 0) AS inserted
            """
        ),
        {"id": new_id, "org": organization_id, "event_type": event_type, "severity": severity, "title": title[:400],
         "body": body, "entity_type": entity_type, "entity_id": entity_id, "dedup": dedup_key[:200], "now": now},
    ).one()
    if not row.inserted:
        return None
    has_rules = db.execute(select(NotificationRule.id).where(NotificationRule.enabled).limit(1)).first()
    if has_rules:
        from app.workers.queue import enqueue

        enqueue(db, organization_id=organization_id, job_type="notifications.deliver",
                config={"notification_id": str(row.id)}, idempotency_key=f"notify:{row.id}")
    return row.id


def matching_rules(db: Session, notification: Notification) -> list[NotificationRule]:
    rules = db.execute(select(NotificationRule).where(NotificationRule.enabled)).scalars()
    return [
        r for r in rules
        if (not r.event_types or notification.event_type in r.event_types)
        and SEVERITY_RANK.get(notification.severity, 0) >= SEVERITY_RANK.get(r.min_severity, 0)
    ]


def deliver(db: Session, notification_id: uuid.UUID) -> dict:
    from app.integrations.notify import channels

    notification = db.get(Notification, notification_id)
    if notification is None:
        return {"delivered": 0, "failed": 0}
    delivered = failed = 0
    for rule in matching_rules(db, notification):
        already = db.execute(
            select(NotificationDelivery.id).where(
                NotificationDelivery.notification_id == notification.id, NotificationDelivery.rule_id == rule.id,
                NotificationDelivery.status == "sent",
            )
        ).first()
        if already:
            continue
        integration = db.get(Integration, rule.integration_id) if rule.integration_id else None
        status, error = "sent", None
        try:
            channels.send(rule, integration, notification)
            delivered += 1
        except Exception as exc:  # delivery failures are recorded per rule, never raised
            status, error = "failed", f"{type(exc).__name__}: {exc}"[:1000]
            failed += 1
            log.warning("notification_delivery_failed", rule_id=str(rule.id), error=error)
        db.execute(
            text(
                """
                INSERT INTO notification_deliveries (id, organization_id, notification_id, rule_id, status, error, attempted_at)
                VALUES (:id, :org, :n, :r, :status, :error, :at)
                ON CONFLICT (notification_id, rule_id) DO UPDATE SET status = :status, error = :error, attempted_at = :at
                """
            ),
            {"id": uuid.uuid4(), "org": notification.organization_id, "n": notification.id, "r": rule.id,
             "status": status, "error": error, "at": datetime.now(UTC)},
        )
    return {"delivered": delivered, "failed": failed}
