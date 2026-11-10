import uuid
from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, EmailStr, Field, model_validator
from sqlalchemy import func, select, text

from app.api.deps import CurrentUser, Db, Paging, Principal, audit_event, paginate, require
from app.core.errors import NotFound, ValidationFailed
from app.db.base import utcnow
from app.domains.notifications import service
from app.models import Integration, Notification, NotificationDelivery, NotificationRead, NotificationRule
from app.workers.queue import JobContext, job_handler

router = APIRouter(prefix="/notifications", tags=["Notifications"])


@job_handler("notifications.deliver")
def deliver_job(job: JobContext, db) -> dict:
    return service.deliver(db, uuid.UUID(job.config["notification_id"]))


class RuleIn(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    event_types: list[str] = []
    min_severity: Literal["info", "low", "medium", "high", "critical"] = "high"
    channel: Literal["email", "webhook", "slack", "teams"]
    integration_id: uuid.UUID | None = None
    email_to: EmailStr | None = None
    enabled: bool = True

    @model_validator(mode="after")
    def _target(self) -> "RuleIn":
        if self.channel == "email" and not self.email_to:
            raise ValueError("email_to is required for the email channel")
        if self.channel != "email" and not self.integration_id:
            raise ValueError("integration_id is required for this channel")
        unknown = set(self.event_types) - set(service.EVENT_TYPES)
        if unknown:
            raise ValueError(f"Unknown event types: {sorted(unknown)}")
        return self


def _rule_out(r: NotificationRule) -> dict:
    return {"id": r.id, "name": r.name, "event_types": r.event_types, "min_severity": r.min_severity,
            "channel": r.channel, "integration_id": r.integration_id, "email_to": r.email_to, "enabled": r.enabled}


@router.get("")
def list_notifications(db: Db, paging: Paging, principal: CurrentUser, unread_only: bool = False) -> dict:
    read = select(NotificationRead.notification_id).where(NotificationRead.user_id == principal.user_id)
    stmt = select(Notification).order_by(Notification.created_at.desc())
    if unread_only:
        stmt = stmt.where(Notification.id.notin_(read))
    rows, total = paginate(db, stmt, paging)
    read_ids = set(db.execute(read.where(NotificationRead.notification_id.in_([n.id for n in rows]))).scalars()) if rows else set()
    unread = db.execute(select(func.count()).select_from(Notification).where(Notification.id.notin_(read))).scalar_one()
    return {"total": total, "unread": unread, "page": paging.page, "page_size": paging.page_size, "items": [
        {"id": n.id, "event_type": n.event_type, "severity": n.severity, "title": n.title, "body": n.body,
         "entity_type": n.entity_type, "entity_id": n.entity_id, "occurrences": n.occurrences,
         "created_at": n.created_at, "read": n.id in read_ids} for n in rows]}


@router.post("/read", status_code=204)
def mark_all_read(db: Db, principal: CurrentUser) -> None:
    db.execute(text(
        """INSERT INTO notification_reads (organization_id, notification_id, user_id, read_at)
           SELECT organization_id, id, :user, :now FROM notifications
           ON CONFLICT DO NOTHING"""), {"user": principal.user_id, "now": utcnow()})


@router.get("/event-types")
def event_types(_: CurrentUser) -> dict:
    return service.EVENT_TYPES


@router.get("/rules")
def list_rules(db: Db, _: Principal = require("notifications:manage")) -> list[dict]:
    return [_rule_out(r) for r in db.execute(select(NotificationRule).order_by(NotificationRule.name)).scalars()]


@router.post("/rules", status_code=201)
def create_rule(body: RuleIn, db: Db, principal: Principal = require("notifications:manage")) -> dict:
    if body.integration_id:
        integration = db.get(Integration, body.integration_id)
        if integration is None or integration.connector != body.channel:
            raise ValidationFailed(f"Select a {body.channel} integration")
    rule = NotificationRule(organization_id=principal.organization_id, **body.model_dump())
    db.add(rule)
    db.flush()
    audit_event(db, principal, "notification.rule_created", entity_type="notification_rule", entity_id=rule.id)
    return _rule_out(rule)


@router.delete("/rules/{rule_id}", status_code=204)
def delete_rule(rule_id: uuid.UUID, db: Db, principal: Principal = require("notifications:manage")) -> None:
    rule = db.get(NotificationRule, rule_id)
    if rule is None:
        raise NotFound("Rule not found")
    db.delete(rule)
    audit_event(db, principal, "notification.rule_deleted", entity_type="notification_rule", entity_id=rule_id)


@router.get("/deliveries")
def list_deliveries(db: Db, paging: Paging, _: Principal = require("notifications:manage")) -> dict:
    rows, total = paginate(db, select(NotificationDelivery).order_by(NotificationDelivery.attempted_at.desc()), paging)
    return {"total": total, "page": paging.page, "page_size": paging.page_size, "items": [
        {"id": d.id, "notification_id": d.notification_id, "rule_id": d.rule_id, "status": d.status, "error": d.error,
         "attempted_at": d.attempted_at} for d in rows]}
