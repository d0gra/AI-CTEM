from datetime import datetime

from fastapi import APIRouter, Query
from sqlalchemy import select

from app.api.deps import Db, Paging, Principal, like_escape, paginate, require
from app.domains.audit import service
from app.models import AuditEvent

router = APIRouter(prefix="/audit", tags=["Audit Logs"])


@router.get("/events")
def list_events(
    db: Db, paging: Paging, _: Principal = require("audit:read"), action: str | None = Query(None, max_length=80),
    actor: str | None = Query(None, max_length=200), outcome: str | None = None, entity_type: str | None = None,
    since: datetime | None = None, until: datetime | None = None,
) -> dict:
    stmt = select(AuditEvent).order_by(AuditEvent.seq.desc())
    if action:
        stmt = stmt.where(AuditEvent.action.ilike(f"{like_escape(action)}%"))
    if actor:
        stmt = stmt.where(AuditEvent.actor_email.ilike(f"%{like_escape(actor)}%"))
    if outcome:
        stmt = stmt.where(AuditEvent.outcome == outcome)
    if entity_type:
        stmt = stmt.where(AuditEvent.entity_type == entity_type)
    if since:
        stmt = stmt.where(AuditEvent.occurred_at >= since)
    if until:
        stmt = stmt.where(AuditEvent.occurred_at <= until)
    rows, total = paginate(db, stmt, paging)
    return {"total": total, "page": paging.page, "page_size": paging.page_size, "items": [
        {"seq": e.seq, "occurred_at": e.occurred_at, "actor_email": e.actor_email, "actor_user_id": e.actor_user_id,
         "action": e.action, "entity_type": e.entity_type, "entity_id": e.entity_id, "outcome": e.outcome,
         "ip_address": e.ip_address, "request_id": e.request_id, "data": e.data, "hash": e.hash} for e in rows]}


@router.get("/verify")
def verify(db: Db, principal: Principal = require("audit:read")) -> dict:
    """Recompute the organization's audit hash chain."""
    return service.verify_chain(db, principal.organization_id)
