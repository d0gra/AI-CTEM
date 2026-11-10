import uuid
from datetime import datetime, timedelta
from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.deps import Db, Principal, audit_event, require
from app.core.errors import Conflict, Forbidden, NotFound, ValidationFailed
from app.db.base import utcnow
from app.domains.policy import rules, service, views
from app.models import Policy, PolicyEvaluation, PolicyException
from app.workers.queue import JobContext, enqueue, job_handler

router = APIRouter(prefix="/policies", tags=["Policies & Compliance"])


@job_handler("policies.evaluate")
def evaluate_job(job: JobContext, db) -> dict:
    results = service.evaluate_all(db)
    return {"policies": len(results), "non_compliant": sum(r.status == "non_compliant" for r in results)}


class PolicyIn(BaseModel):
    key: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,78}$")
    name: str = Field(min_length=3, max_length=300)
    description: str = Field(default="", max_length=4000)
    severity: Literal["critical", "high", "medium", "low"]
    entity_type: Literal["asset", "finding"]
    scope: dict = {}
    condition: dict
    framework_refs: list[str] = Field(default=[], max_length=20)
    enabled: bool = True


class PolicyPatch(BaseModel):
    name: str | None = Field(default=None, min_length=3, max_length=300)
    description: str | None = Field(default=None, max_length=4000)
    severity: Literal["critical", "high", "medium", "low"] | None = None
    scope: dict | None = None
    condition: dict | None = None
    framework_refs: list[str] | None = None
    enabled: bool | None = None


class ExceptionIn(BaseModel):
    entity_id: uuid.UUID
    reason: str = Field(min_length=20, max_length=4000)
    expires_at: datetime


class DecisionIn(BaseModel):
    approve: bool


def _latest(db: Db, policy_id: uuid.UUID) -> PolicyEvaluation | None:
    return db.execute(select(PolicyEvaluation).where(PolicyEvaluation.policy_id == policy_id)
                      .order_by(PolicyEvaluation.evaluated_at.desc()).limit(1)).scalar_one_or_none()


def _eval_out(e: PolicyEvaluation | None, with_violations: bool = False) -> dict | None:
    if e is None:
        return None
    out = {"id": e.id, "evaluated_at": e.evaluated_at, "total": e.total, "passed": e.passed, "failed": e.failed,
           "exempt": e.exempt, "status": e.status}
    if with_violations:
        out["violations"] = e.violations
    return out


def _out(db: Db, p: Policy, detail: bool = False) -> dict:
    return {"id": p.id, "key": p.key, "name": p.name, "description": p.description, "severity": p.severity,
            "entity_type": p.entity_type, "scope": p.scope, "condition": p.condition, "framework_refs": p.framework_refs,
            "enabled": p.enabled, "last_evaluated_at": p.last_evaluated_at,
            "latest_evaluation": _eval_out(_latest(db, p.id), with_violations=detail)}


def _get(db: Db, policy_id: uuid.UUID) -> Policy:
    p = db.get(Policy, policy_id)
    if p is None:
        raise NotFound("Policy not found")
    return p


@router.get("")
def list_policies(db: Db, _: Principal = require("policies:read")) -> dict:
    policies = [_out(db, p) for p in db.execute(select(Policy).order_by(Policy.name)).scalars()]
    evaluated = [p for p in policies if p["latest_evaluation"] and p["enabled"] and p["latest_evaluation"]["status"] != "not_applicable"]
    compliant = sum(1 for p in evaluated if p["latest_evaluation"]["status"] == "compliant")
    return {"items": policies,
            "summary": {"total": len(policies), "evaluated": len(evaluated), "compliant": compliant,
                        "non_compliant": len(evaluated) - compliant,
                        "compliance_percent": round(100 * compliant / len(evaluated), 1) if evaluated else None},
            "fields": {"asset": views.ASSET_FIELDS, "finding": views.FINDING_FIELDS}, "operators": sorted(rules.OPERATORS)}


@router.post("", status_code=201)
def create_policy(body: PolicyIn, db: Db, principal: Principal = require("policies:manage")) -> dict:
    rules.validate_rule(body.scope)
    rules.validate_rule(body.condition)
    if not body.condition:
        raise ValidationFailed("A policy condition is required")
    if db.execute(select(Policy.id).where(Policy.key == body.key)).first():
        raise Conflict("A policy with this key already exists")
    policy = Policy(organization_id=principal.organization_id, **body.model_dump())
    db.add(policy)
    db.flush()
    audit_event(db, principal, "policy.created", entity_type="policy", entity_id=policy.id, data={"key": policy.key})
    return _out(db, policy)


@router.get("/{policy_id}")
def get_policy(policy_id: uuid.UUID, db: Db, _: Principal = require("policies:read")) -> dict:
    p = _get(db, policy_id)
    history = db.execute(select(PolicyEvaluation).where(PolicyEvaluation.policy_id == p.id)
                         .order_by(PolicyEvaluation.evaluated_at.desc()).limit(30)).scalars()
    exceptions = db.execute(select(PolicyException).where(PolicyException.policy_id == p.id)
                            .order_by(PolicyException.created_at.desc())).scalars()
    return {**_out(db, p, detail=True), "history": [_eval_out(e) for e in history],
            "exceptions": [{"id": x.id, "entity_id": x.entity_id, "reason": x.reason, "status": x.status,
                            "expires_at": x.expires_at, "requested_by_user_id": x.requested_by_user_id,
                            "decided_by_user_id": x.decided_by_user_id} for x in exceptions]}


@router.patch("/{policy_id}")
def update_policy(policy_id: uuid.UUID, body: PolicyPatch, db: Db, principal: Principal = require("policies:manage")) -> dict:
    p = _get(db, policy_id)
    changes = body.model_dump(exclude_unset=True)
    for key in ("scope", "condition"):
        if changes.get(key) is not None:
            rules.validate_rule(changes[key])
    if "condition" in changes and not changes["condition"]:
        raise ValidationFailed("A policy condition is required")
    for key, value in changes.items():
        setattr(p, key, value)
    audit_event(db, principal, "policy.updated", entity_type="policy", entity_id=p.id, data={"fields": sorted(changes)})
    return _out(db, p)


@router.delete("/{policy_id}", status_code=204)
def delete_policy(policy_id: uuid.UUID, db: Db, principal: Principal = require("policies:manage")) -> None:
    p = _get(db, policy_id)
    db.delete(p)
    audit_event(db, principal, "policy.deleted", entity_type="policy", entity_id=policy_id, data={"key": p.key})


@router.post("/{policy_id}/evaluate")
def evaluate_one(policy_id: uuid.UUID, db: Db, principal: Principal = require("policies:read")) -> dict:
    evaluation = service.evaluate_policy(db, _get(db, policy_id))
    audit_event(db, principal, "policy.evaluated", entity_type="policy", entity_id=policy_id,
                data={"status": evaluation.status, "failed": evaluation.failed})
    return _eval_out(evaluation, with_violations=True)  # type: ignore[return-value]


@router.post("/evaluate", status_code=202)
def evaluate_everything(db: Db, principal: Principal = require("policies:read")) -> dict:
    job = enqueue(db, organization_id=principal.organization_id, job_type="policies.evaluate",
                  idempotency_key="policies.evaluate", created_by_user_id=principal.user_id)
    return {"job_id": job.id}


@router.post("/{policy_id}/exceptions", status_code=201)
def request_exception(policy_id: uuid.UUID, body: ExceptionIn, db: Db, principal: Principal = require("risk:request")) -> dict:
    p = _get(db, policy_id)
    if not utcnow() < body.expires_at <= utcnow() + timedelta(days=365):
        raise ValidationFailed("Expiration must be within the next 365 days")
    exception = PolicyException(organization_id=principal.organization_id, policy_id=p.id, entity_id=body.entity_id,
                                reason=body.reason, requested_by_user_id=principal.user_id, expires_at=body.expires_at)
    db.add(exception)
    db.flush()
    audit_event(db, principal, "policy.exception_requested", entity_type="policy_exception", entity_id=exception.id)
    return {"id": exception.id, "status": exception.status}


@router.post("/exceptions/{exception_id}/decision")
def decide_exception(exception_id: uuid.UUID, body: DecisionIn, db: Db, principal: Principal = require("risk:approve")) -> dict:
    exception = db.get(PolicyException, exception_id)
    if exception is None:
        raise NotFound("Exception not found")
    if exception.status != "pending":
        raise Conflict(f"This exception is already {exception.status}")
    if exception.requested_by_user_id == principal.user_id:
        raise Forbidden("You cannot decide your own exception request")
    exception.status = "approved" if body.approve else "rejected"
    exception.decided_by_user_id, exception.decided_at = principal.user_id, utcnow()
    audit_event(db, principal, f"policy.exception_{exception.status}", entity_type="policy_exception", entity_id=exception.id)
    return {"id": exception.id, "status": exception.status}
