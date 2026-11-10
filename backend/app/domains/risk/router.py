import uuid
from datetime import datetime, timedelta

from fastapi import APIRouter
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.deps import Db, Paging, Principal, audit_event, paginate, require
from app.core.errors import Conflict, Forbidden, NotFound, ValidationFailed
from app.db.base import utcnow
from app.domains.findings import service as findings
from app.domains.notifications.service import notify
from app.domains.risk import service
from app.domains.risk.policy import RiskPolicy, load_policy, save_policy
from app.models import Finding, RiskAcceptance, User
from app.models.finding import OPEN_STATUSES
from app.workers.queue import JobContext, enqueue, job_handler

router = APIRouter(prefix="/risk", tags=["Risk Management"])


@job_handler("risk.recalculate")
def recalculate_job(job: JobContext, db) -> dict:
    return service.recalculate_all(db, job.organization_id)


@job_handler("risk.expire_acceptances")
def expire_acceptances_job(job: JobContext, db) -> dict:
    """Return findings to triage when their risk acceptance has expired."""
    expired = 0
    rows = db.execute(select(RiskAcceptance).where(RiskAcceptance.status == "approved",
                                                   RiskAcceptance.expires_at <= utcnow())).scalars()
    for acceptance in rows:
        acceptance.status = "expired"
        finding = db.get(Finding, acceptance.finding_id)
        if finding is not None and finding.status == "accepted_risk":
            finding.status, finding.resolved_at, finding.due_at = "triaged", None, None
            findings.add_event(db, finding, "status_changed", {"from": "accepted_risk", "to": "triaged",
                                                               "reason": "Risk acceptance expired"})
            service.score_finding(db, finding)
            notify(db, organization_id=job.organization_id, event_type="risk.acceptance_requested", severity="medium",
                   title=f"Risk acceptance expired: {finding.title}", entity_type="finding", entity_id=finding.id)
        expired += 1
    return {"expired": expired}


class AcceptanceIn(BaseModel):
    finding_id: uuid.UUID
    reason: str = Field(min_length=20, max_length=5000)
    compensating_controls: str = Field(default="", max_length=5000)
    owner_user_id: uuid.UUID
    expires_at: datetime


class DecisionIn(BaseModel):
    approve: bool
    note: str = Field(default="", max_length=2000)


def _out(a: RiskAcceptance, finding: Finding | None = None) -> dict:
    return {"id": a.id, "finding_id": a.finding_id, "finding_title": finding.title if finding else None,
            "finding_risk_level": finding.risk_level if finding else None, "owner_user_id": a.owner_user_id,
            "requested_by_user_id": a.requested_by_user_id, "reason": a.reason,
            "compensating_controls": a.compensating_controls, "status": a.status, "decision_note": a.decision_note,
            "decided_by_user_id": a.decided_by_user_id, "decided_at": a.decided_at, "expires_at": a.expires_at,
            "created_at": a.created_at}


@router.get("/policy")
def get_policy(db: Db, principal: Principal = require("risk:read")) -> dict:
    return load_policy(db, principal.organization_id).model_dump()


@router.put("/policy")
def put_policy(body: RiskPolicy, db: Db, principal: Principal = require("risk:configure")) -> dict:
    policy = save_policy(db, principal.organization_id, body)
    job = enqueue(db, organization_id=principal.organization_id, job_type="risk.recalculate",
                  idempotency_key="risk.recalculate", created_by_user_id=principal.user_id)
    audit_event(db, principal, "risk.policy_updated", entity_type="organization", entity_id=principal.organization_id,
                data={"version": policy.version, "thresholds": policy.thresholds.model_dump(), "sla_hours": policy.sla_hours})
    return {**policy.model_dump(), "recalculation_job_id": job.id}


@router.post("/recalculate", status_code=202)
def recalculate(db: Db, principal: Principal = require("risk:configure")) -> dict:
    job = enqueue(db, organization_id=principal.organization_id, job_type="risk.recalculate",
                  idempotency_key="risk.recalculate", created_by_user_id=principal.user_id)
    return {"job_id": job.id}


@router.get("/acceptances")
def list_acceptances(db: Db, paging: Paging, _: Principal = require("risk:read"), status: str | None = None) -> dict:
    stmt = (select(RiskAcceptance, Finding).join(Finding, Finding.id == RiskAcceptance.finding_id)
            .order_by(RiskAcceptance.created_at.desc()))
    if status:
        stmt = stmt.where(RiskAcceptance.status == status)
    rows, total = paginate(db, stmt, paging, scalars=False)
    return {"items": [_out(a, f) for a, f in rows], "total": total, "page": paging.page, "page_size": paging.page_size}


@router.post("/acceptances", status_code=201)
def request_acceptance(body: AcceptanceIn, db: Db, principal: Principal = require("risk:request")) -> dict:
    finding = db.get(Finding, body.finding_id)
    if finding is None:
        raise NotFound("Finding not found")
    if finding.status not in OPEN_STATUSES:
        raise Conflict(f"Risk cannot be accepted for a {finding.status} finding")
    if db.get(User, body.owner_user_id) is None:
        raise ValidationFailed("Risk owner does not exist")
    policy = load_policy(db, principal.organization_id)
    now = utcnow()
    if body.expires_at <= now:
        raise ValidationFailed("Expiration must be in the future")
    if body.expires_at > now + timedelta(days=policy.risk_acceptance_max_days):
        raise ValidationFailed(f"Risk acceptance may not exceed {policy.risk_acceptance_max_days} days")
    pending = db.execute(select(RiskAcceptance.id).where(RiskAcceptance.finding_id == finding.id,
                                                         RiskAcceptance.status == "pending")).first()
    if pending:
        raise Conflict("A risk acceptance request is already pending for this finding")
    acceptance = RiskAcceptance(organization_id=principal.organization_id, finding_id=finding.id,
                                owner_user_id=body.owner_user_id, requested_by_user_id=principal.user_id,
                                reason=body.reason, compensating_controls=body.compensating_controls,
                                expires_at=body.expires_at)
    db.add(acceptance)
    db.flush()
    findings.add_event(db, finding, "risk_acceptance_requested", {"acceptance_id": str(acceptance.id)}, principal.user_id)
    notify(db, organization_id=principal.organization_id, event_type="risk.acceptance_requested", severity="medium",
           title=f"Risk acceptance requested: {finding.title}", body=body.reason[:400], entity_type="finding",
           entity_id=finding.id)
    audit_event(db, principal, "risk.acceptance_requested", entity_type="risk_acceptance", entity_id=acceptance.id,
                data={"finding_id": str(finding.id), "expires_at": body.expires_at.isoformat()})
    return _out(acceptance, finding)


@router.post("/acceptances/{acceptance_id}/decision")
def decide_acceptance(acceptance_id: uuid.UUID, body: DecisionIn, db: Db, principal: Principal = require("risk:approve")) -> dict:
    acceptance = db.get(RiskAcceptance, acceptance_id)
    if acceptance is None:
        raise NotFound("Risk acceptance not found")
    if acceptance.status != "pending":
        raise Conflict(f"This request is already {acceptance.status}")
    if acceptance.requested_by_user_id == principal.user_id:
        raise Forbidden("You cannot approve or reject your own risk acceptance request")
    finding = db.get(Finding, acceptance.finding_id)
    assert finding is not None
    acceptance.status = "approved" if body.approve else "rejected"
    acceptance.decided_by_user_id, acceptance.decided_at, acceptance.decision_note = principal.user_id, utcnow(), body.note
    if body.approve and finding.status in OPEN_STATUSES:
        findings.transition(db, finding, "accepted_risk", actor_user_id=principal.user_id, force=True,
                            note=f"Risk accepted until {acceptance.expires_at.date()}")
    findings.add_event(db, finding, "risk_acceptance_decided", {"acceptance_id": str(acceptance.id),
                                                                "decision": acceptance.status, "note": body.note}, principal.user_id)
    audit_event(db, principal, f"risk.acceptance_{acceptance.status}", entity_type="risk_acceptance", entity_id=acceptance.id,
                data={"finding_id": str(finding.id), "note": body.note})
    return _out(acceptance, finding)


@router.post("/acceptances/{acceptance_id}/revoke")
def revoke_acceptance(acceptance_id: uuid.UUID, db: Db, principal: Principal = require("risk:approve")) -> dict:
    acceptance = db.get(RiskAcceptance, acceptance_id)
    if acceptance is None:
        raise NotFound("Risk acceptance not found")
    if acceptance.status != "approved":
        raise Conflict("Only approved acceptances can be revoked")
    acceptance.status = "revoked"
    finding = db.get(Finding, acceptance.finding_id)
    if finding is not None and finding.status == "accepted_risk":
        findings.transition(db, finding, "triaged", actor_user_id=principal.user_id, note="Risk acceptance revoked")
        finding.due_at = None
        service.score_finding(db, finding)
    audit_event(db, principal, "risk.acceptance_revoked", entity_type="risk_acceptance", entity_id=acceptance.id)
    return _out(acceptance, finding)
