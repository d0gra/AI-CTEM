import uuid

from fastapi import APIRouter, Query
from sqlalchemy import select

from app.api.deps import Db, Paging, Principal, audit_event, paginate, require
from app.core.errors import NotFound
from app.domains.attack_paths import engine
from app.models import Asset, AttackPath, Finding
from app.workers.queue import JobContext, enqueue, job_handler

router = APIRouter(tags=["Attack Paths"])


@job_handler("attack_paths.compute")
def compute_job(job: JobContext, db) -> dict:
    return engine.compute(db, job.organization_id)


def _summary(p: AttackPath) -> dict:
    return {"id": p.id, "title": p.title, "classification": p.classification, "confidence": p.confidence,
            "score": p.score, "severity": p.severity, "involves_ai": p.involves_ai, "status": p.status,
            "entry_asset_id": p.entry_asset_id, "target_asset_id": p.target_asset_id, "steps": len(p.edges),
            "first_seen_at": p.first_seen_at, "last_computed_at": p.last_computed_at}


@router.get("/attack-paths")
def list_paths(
    db: Db, paging: Paging, _: Principal = require("attack_paths:read"),
    classification: list[str] | None = Query(None), severity: list[str] | None = Query(None),
    involves_ai: bool | None = None, status: str = "active", asset_id: uuid.UUID | None = None,
) -> dict:
    stmt = select(AttackPath).where(AttackPath.status == status).order_by(AttackPath.score.desc(), AttackPath.id)
    if classification:
        stmt = stmt.where(AttackPath.classification.in_(classification))
    if severity:
        stmt = stmt.where(AttackPath.severity.in_(severity))
    if involves_ai is not None:
        stmt = stmt.where(AttackPath.involves_ai.is_(involves_ai))
    if asset_id:
        from app.models import AttackPathNode

        stmt = stmt.where(AttackPath.id.in_(select(AttackPathNode.attack_path_id).where(AttackPathNode.asset_id == asset_id)))
    rows, total = paginate(db, stmt, paging)
    return {"items": [_summary(p) for p in rows], "total": total, "page": paging.page, "page_size": paging.page_size}


@router.get("/attack-paths/{path_id}")
def get_path(path_id: uuid.UUID, db: Db, _: Principal = require("attack_paths:read")) -> dict:
    p = db.get(AttackPath, path_id)
    if p is None:
        raise NotFound("Attack path not found")
    assets = {a.id: a for a in db.execute(select(Asset).where(Asset.id.in_([n.asset_id for n in p.nodes]))).scalars()}
    finding_ids = {uuid.UUID(f) for n in p.nodes for f in n.finding_ids} | {e.enabling_finding_id for e in p.edges if e.enabling_finding_id}
    findings = {f.id: f for f in db.execute(select(Finding).where(Finding.id.in_(finding_ids))).scalars()} if finding_ids else {}

    def brief(fid) -> dict | None:
        f = findings.get(fid)
        return {"id": f.id, "title": f.title, "severity": f.severity, "confidence": f.confidence, "status": f.status,
                "risk_score": f.risk_score} if f else None

    return {
        **_summary(p), "business_impact": p.business_impact, "required_conditions": p.required_conditions,
        "remediation_opportunities": p.remediation_opportunities,
        "nodes": [{
            "position": n.position, "asset_id": n.asset_id, "label": n.label, "type": n.node_type,
            "crosses_trust_boundary": n.crosses_trust_boundary,
            "exposure": assets[n.asset_id].exposure if n.asset_id in assets else None,
            "criticality": assets[n.asset_id].criticality if n.asset_id in assets else None,
            "data_sensitivity": assets[n.asset_id].data_sensitivity if n.asset_id in assets else None,
            "role": "entry" if n.position == 0 else ("target" if n.position == len(p.nodes) - 1 else "intermediate"),
            "findings": [b for b in (brief(uuid.UUID(f)) for f in n.finding_ids) if b],
        } for n in p.nodes],
        "edges": [{
            "position": e.position, "relationship_type": e.relationship_type, "relationship_id": e.relationship_id,
            "technique": e.technique, "condition": e.condition, "evidence_level": e.evidence_level,
            "enabling_finding": brief(e.enabling_finding_id),
        } for e in p.edges],
    }


@router.post("/attack-paths/compute", status_code=202)
def recompute(db: Db, principal: Principal = require("attack_paths:compute")) -> dict:
    job = enqueue(db, organization_id=principal.organization_id, job_type="attack_paths.compute",
                  idempotency_key="attack_paths.compute", created_by_user_id=principal.user_id)
    audit_event(db, principal, "attack_paths.compute_requested", entity_type="job", entity_id=job.id)
    return {"job_id": job.id, "state": job.state}
