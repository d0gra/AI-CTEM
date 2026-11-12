import json
import uuid
from datetime import datetime
from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.deps import Db, Paging, Principal, audit_event, paginate, require
from app.core.config import get_settings
from app.core.errors import Conflict, NotFound, UpstreamError, ValidationFailed
from app.core.security import decrypt_secret
from app.db.base import utcnow
from app.domains.findings import service as findings
from app.domains.notifications.service import notify
from app.integrations.base import ApiError
from app.integrations.ticketing.connectors import TICKETING, create_ticket
from app.models import Asset, Finding, Integration, RemediationTask, Team, User
from app.models.finding import OPEN_STATUSES
from app.workers.queue import JobContext, job_handler

router = APIRouter(prefix="/remediation", tags=["Remediation"])
TASK_STATUSES = ("open", "in_progress", "pending_validation", "done", "cancelled")


@job_handler("remediation.sla_check")
def sla_check_job(job: JobContext, db) -> dict:
    """Notify once per finding per day while an open finding is past its due date."""
    now = utcnow()
    overdue = db.execute(select(Finding).where(Finding.due_at < now, Finding.status.in_(OPEN_STATUSES))).scalars()
    count = 0
    for finding in overdue:
        count += 1
        notify(db, organization_id=job.organization_id, event_type="sla.breached",
               severity="critical" if finding.risk_level == "critical" else "high",
               title=f"Remediation SLA breached: {finding.title}",
               body=f"Due {finding.due_at:%Y-%m-%d}; risk level {finding.risk_level}.", entity_type="finding",
               entity_id=finding.id)
        for task in db.execute(select(RemediationTask).where(RemediationTask.finding_id == finding.id,
                                                             RemediationTask.status.in_(("open", "in_progress")))).scalars():
            task.overdue_notified_at = now
    return {"overdue": count}


class TaskIn(BaseModel):
    finding_id: uuid.UUID
    title: str | None = Field(default=None, max_length=512)
    instructions: str = Field(default="", max_length=20000)
    priority: Literal["critical", "high", "medium", "low"] | None = None
    assignee_user_id: uuid.UUID | None = None
    team_id: uuid.UUID | None = None
    due_at: datetime | None = None


class TaskPatch(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=512)
    instructions: str | None = Field(default=None, max_length=20000)
    status: Literal[TASK_STATUSES] | None = None  # type: ignore[valid-type]
    priority: Literal["critical", "high", "medium", "low"] | None = None
    assignee_user_id: uuid.UUID | None = None
    team_id: uuid.UUID | None = None
    due_at: datetime | None = None


class TicketIn(BaseModel):
    integration_id: uuid.UUID
    # Creating a ticket writes to an external system; the caller must confirm explicitly.
    confirm: bool


def _out(t: RemediationTask, finding: Finding | None = None) -> dict:
    now = utcnow()
    return {"id": t.id, "finding_id": t.finding_id, "finding_title": finding.title if finding else None,
            "finding_status": finding.status if finding else None, "finding_risk_level": finding.risk_level if finding else None,
            "title": t.title, "instructions": t.instructions, "status": t.status, "priority": t.priority,
            "assignee_user_id": t.assignee_user_id, "team_id": t.team_id, "due_at": t.due_at,
            "overdue": bool(t.due_at and t.due_at < now and t.status in ("open", "in_progress")),
            "completed_at": t.completed_at, "verified_at": t.verified_at, "ticket_system": t.ticket_system,
            "ticket_key": t.ticket_key, "ticket_url": t.ticket_url, "created_at": t.created_at}


def _check_people(db: Db, user_id: uuid.UUID | None, team_id: uuid.UUID | None) -> None:
    if user_id and db.get(User, user_id) is None:
        raise ValidationFailed("Assignee does not exist")
    if team_id and db.get(Team, team_id) is None:
        raise ValidationFailed("Team does not exist")


@router.get("/tasks")
def list_tasks(db: Db, paging: Paging, principal: Principal = require("remediation:read"), status: str | None = None,
               assignee_user_id: uuid.UUID | None = None, team_id: uuid.UUID | None = None, overdue: bool = False,
               finding_id: uuid.UUID | None = None, mine: bool = False) -> dict:
    if mine:
        assignee_user_id = principal.user_id
    stmt = (select(RemediationTask, Finding).join(Finding, Finding.id == RemediationTask.finding_id)
            .order_by(RemediationTask.due_at.asc().nulls_last(), RemediationTask.created_at.desc()))
    for column, value in ((RemediationTask.status, status), (RemediationTask.assignee_user_id, assignee_user_id),
                          (RemediationTask.team_id, team_id), (RemediationTask.finding_id, finding_id)):
        if value:
            stmt = stmt.where(column == value)
    if overdue:
        stmt = stmt.where(RemediationTask.due_at < utcnow(), RemediationTask.status.in_(("open", "in_progress")))
    rows, total = paginate(db, stmt, paging, scalars=False)
    return {"items": [_out(t, f) for t, f in rows], "total": total, "page": paging.page, "page_size": paging.page_size}


@router.post("/tasks", status_code=201)
def create_task(body: TaskIn, db: Db, principal: Principal = require("remediation:write")) -> dict:
    finding = db.get(Finding, body.finding_id)
    if finding is None:
        raise NotFound("Finding not found")
    if finding.status not in OPEN_STATUSES:
        raise Conflict(f"Cannot create a remediation task for a {finding.status} finding")
    _check_people(db, body.assignee_user_id, body.team_id)
    task = RemediationTask(
        organization_id=principal.organization_id, finding_id=finding.id, title=body.title or f"Remediate: {finding.title}"[:512],
        instructions=body.instructions or finding.remediation,
        priority=body.priority or (finding.risk_level if finding.risk_level in ("critical", "high", "medium", "low") else "low"),
        assignee_user_id=body.assignee_user_id, team_id=body.team_id, due_at=body.due_at or finding.due_at,
        created_by_user_id=principal.user_id)
    db.add(task)
    db.flush()
    if body.assignee_user_id or body.team_id:
        finding.owner_user_id = finding.owner_user_id or body.assignee_user_id
        finding.owner_team_id = finding.owner_team_id or body.team_id
        if finding.status in ("new", "triaged"):
            findings.transition(db, finding, "assigned", actor_user_id=principal.user_id, note="Remediation task created")
    findings.add_event(db, finding, "remediation_task_created", {"task_id": str(task.id)}, principal.user_id)
    audit_event(db, principal, "remediation.task_created", entity_type="remediation_task", entity_id=task.id)
    return _out(task, finding)


@router.patch("/tasks/{task_id}")
def update_task(task_id: uuid.UUID, body: TaskPatch, db: Db, principal: Principal = require("remediation:write")) -> dict:
    task = db.get(RemediationTask, task_id)
    if task is None:
        raise NotFound("Task not found")
    finding = db.get(Finding, task.finding_id)
    assert finding is not None
    changes = body.model_dump(exclude_unset=True)
    _check_people(db, changes.get("assignee_user_id"), changes.get("team_id"))
    new_status = changes.pop("status", None)
    for key, value in changes.items():
        setattr(task, key, value)
    if new_status and new_status != task.status:
        if new_status == "done":
            raise ValidationFailed("Tasks are completed when the finding is verified as remediated; "
                                   "move the task to pending_validation and retest the finding")
        task.status = new_status
        if new_status == "in_progress" and finding.status in ("new", "triaged", "assigned"):
            findings.transition(db, finding, "in_progress", actor_user_id=principal.user_id, note="Remediation started")
        if new_status == "pending_validation":
            task.completed_at = utcnow()
            if finding.status in OPEN_STATUSES and finding.status != "pending_validation":
                findings.transition(db, finding, "pending_validation", actor_user_id=principal.user_id, force=True,
                                    note="Fix reported; awaiting retest")
    audit_event(db, principal, "remediation.task_updated", entity_type="remediation_task", entity_id=task.id,
                data=body.model_dump(exclude_unset=True, mode="json"))
    return _out(task, finding)


@router.post("/tasks/{task_id}/ticket")
def create_external_ticket(task_id: uuid.UUID, body: TicketIn, db: Db, principal: Principal = require("remediation:write")) -> dict:
    task = db.get(RemediationTask, task_id)
    if task is None:
        raise NotFound("Task not found")
    if not body.confirm:
        raise ValidationFailed("Creating an external ticket must be confirmed")
    if task.ticket_key:
        raise Conflict("This task already has a ticket", details={"ticket_url": task.ticket_url})
    integration = db.get(Integration, body.integration_id)
    if integration is None or integration.connector not in TICKETING or not integration.enabled:
        raise ValidationFailed("Select an enabled ticketing integration")
    finding = db.get(Finding, task.finding_id)
    asset = db.get(Asset, finding.asset_id) if finding else None
    assert finding is not None
    link = f"{get_settings().public_base_url}/findings/{finding.id}"
    text = "\n\n".join([
        f"Security finding: {finding.title}",
        f"Risk: {finding.risk_level} ({finding.risk_score}) | Severity: {finding.severity} | Asset: {asset.name if asset else 'n/a'}",
        f"Description:\n{finding.description[:3000]}" if finding.description else "",
        f"Remediation:\n{task.instructions[:3000]}" if task.instructions else "",
        f"Due: {task.due_at:%Y-%m-%d}" if task.due_at else "",
        f"Details and evidence: {link}",
    ])
    credentials = json.loads(decrypt_secret(integration.credentials_encrypted)) if integration.credentials_encrypted else {}
    try:
        ticket = create_ticket(integration.connector, integration.config, credentials, title=task.title, body=text)
    except ApiError as exc:
        integration.health, integration.last_error, integration.last_error_class = "error", str(exc)[:1000], exc.error_class
        integration.last_checked_at = utcnow()
        audit_event(db, principal, "remediation.ticket_failed", entity_type="remediation_task", entity_id=task.id,
                    outcome="failure", data={"error_class": exc.error_class})
        db.commit()
        raise UpstreamError(f"Ticket creation failed ({exc.error_class})", details={"error": str(exc)[:300]}) from exc
    task.ticket_system, task.ticket_key, task.ticket_url = ticket.system, ticket.key, ticket.url
    findings.add_event(db, finding, "ticket_created", {"system": ticket.system, "key": ticket.key, "url": ticket.url}, principal.user_id)
    audit_event(db, principal, "remediation.ticket_created", entity_type="remediation_task", entity_id=task.id,
                data={"system": ticket.system, "key": ticket.key})
    return _out(task, finding)
