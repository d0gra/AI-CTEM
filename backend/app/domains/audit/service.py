"""Audit log writer and verifier.

Events for an organization form a hash chain: hash = SHA-256(prev_hash || canonical event).
The application database role cannot UPDATE or DELETE audit rows; the chain additionally makes
out-of-band tampering by a more privileged actor detectable.
"""

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.core.context import get_request_context
from app.db.base import utcnow
from app.models import AuditEvent

GENESIS = "0" * 64
_SECRET_KEYS = ("password", "secret", "token", "credential", "api_key", "authorization")


def _scrub(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: ("[redacted]" if any(s in k.lower() for s in _SECRET_KEYS) else _scrub(v)) for k, v in value.items()
        }
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    if isinstance(value, uuid.UUID | datetime):
        return str(value)
    return value


def _digest(prev_hash: str, payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256((prev_hash + canonical).encode()).hexdigest()


def _payload(e: AuditEvent) -> dict:
    return {
        "organization_id": str(e.organization_id),
        "occurred_at": e.occurred_at.astimezone(UTC).isoformat(),
        "actor_user_id": str(e.actor_user_id) if e.actor_user_id else None,
        "actor_email": e.actor_email,
        "action": e.action,
        "entity_type": e.entity_type,
        "entity_id": e.entity_id,
        "outcome": e.outcome,
        "ip_address": e.ip_address,
        "request_id": e.request_id,
        "data": e.data,
    }


def record(
    db: Session,
    *,
    organization_id: uuid.UUID,
    action: str,
    actor_user_id: uuid.UUID | None = None,
    actor_email: str | None = None,
    entity_type: str | None = None,
    entity_id: Any = None,
    outcome: str = "success",
    data: dict | None = None,
) -> AuditEvent:
    ctx = get_request_context()
    # Serialise chain extension per organization for the duration of the transaction.
    db.execute(text("select pg_advisory_xact_lock(hashtext(:k))"), {"k": f"audit:{organization_id}"})
    prev = db.execute(
        select(AuditEvent.hash)
        .where(AuditEvent.organization_id == organization_id)
        .order_by(AuditEvent.seq.desc())
        .limit(1)
    ).scalar_one_or_none()
    event = AuditEvent(
        organization_id=organization_id,
        occurred_at=utcnow(),
        actor_user_id=actor_user_id,
        actor_email=actor_email,
        action=action,
        entity_type=entity_type,
        entity_id=str(entity_id) if entity_id is not None else None,
        outcome=outcome,
        ip_address=ctx.ip_address,
        request_id=ctx.request_id or None,
        data=_scrub(data or {}),
        prev_hash=prev or GENESIS,
        hash="",
    )
    event.hash = _digest(event.prev_hash, _payload(event))
    db.add(event)
    db.flush()
    return event


def verify_chain(db: Session, organization_id: uuid.UUID) -> dict:
    """Recompute the chain for an organization and report the first inconsistency, if any."""
    prev = GENESIS
    count = 0
    rows = db.execute(
        select(AuditEvent).where(AuditEvent.organization_id == organization_id).order_by(AuditEvent.seq)
    ).scalars()
    for event in rows:
        count += 1
        if event.prev_hash != prev or event.hash != _digest(prev, _payload(event)):
            return {"valid": False, "events": count, "first_invalid_seq": event.seq}
        prev = event.hash
    return {"valid": True, "events": count, "first_invalid_seq": None}
