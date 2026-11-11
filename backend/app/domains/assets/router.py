import uuid
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, or_, select

from app.api.deps import Db, Page, Paging, Principal, audit_event, like_escape, paginate, require
from app.core.errors import Conflict, NotFound, ValidationFailed
from app.db.base import utcnow
from app.domains.assets import scope as scope_service
from app.domains.assets.service import AssetSpec, link_assets, upsert_asset
from app.models import (
    AIAgent,
    AIAsset,
    AIModel,
    Asset,
    AssetDiscoveryEvent,
    AssetRelationship,
    Finding,
    MCPServer,
    ScopeTarget,
    Team,
    User,
)
from app.models.asset import (
    AI_ASSET_TYPES,
    ASSET_TYPES,
    CRITICALITIES,
    ENVIRONMENTS,
    EXPOSURES,
    RELATIONSHIP_TYPES,
    SENSITIVITIES,
)
from app.models.finding import OPEN_STATUSES
from app.workers.queue import JobContext, job_handler

router = APIRouter(tags=["Assets"])


@job_handler("assets.mark_stale")
def mark_stale_job(job: JobContext, db) -> dict:
    """Assets that automated discovery has not observed for CTEM_ASSET_STALE_DAYS are marked stale.

    Manually registered assets are exempt. A stale asset becomes active again when re-observed."""
    from datetime import timedelta

    from app.core.config import get_settings

    cutoff = utcnow() - timedelta(days=get_settings().asset_stale_days)
    count = 0
    for asset in db.execute(select(Asset).where(Asset.status == "active", Asset.last_seen_at < cutoff)).scalars():
        if set(asset.discovery_sources) <= {"manual"}:
            continue
        asset.status = "stale"
        db.add(AssetDiscoveryEvent(organization_id=asset.organization_id, asset_id=asset.id, event_type="stale", source="system",
                                   details={"last_seen_at": asset.last_seen_at.isoformat()}, occurred_at=utcnow()))
        count += 1
    return {"marked_stale": count}

SORTABLE = {"name": Asset.name, "type": Asset.type, "risk_score": Asset.risk_score,
            "last_seen_at": Asset.last_seen_at, "first_seen_at": Asset.first_seen_at, "exposure": Asset.exposure}


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    type: str
    identifier: str
    name: str
    description: str
    environment: str
    criticality: str
    exposure: str
    data_sensitivity: str
    business_unit: str | None
    owner_user_id: uuid.UUID | None
    owner_team_id: uuid.UUID | None
    tags: list[str]
    discovery_sources: list[str]
    status: str
    risk_score: float
    first_seen_at: datetime
    last_seen_at: datetime
    open_findings: int = 0


class AssetDetail(AssetOut):
    attributes: dict
    ai: dict | None = None
    agent: dict | None = None
    mcp: dict | None = None
    model: dict | None = None
    findings_by_severity: dict[str, int] = {}


class AssetIn(BaseModel):
    type: str
    identifier: str = Field(min_length=1, max_length=1024)
    name: str | None = Field(default=None, max_length=512)
    description: str = ""
    environment: Literal[ENVIRONMENTS] = "unknown"  # type: ignore[valid-type]
    criticality: Literal[CRITICALITIES] = "medium"  # type: ignore[valid-type]
    exposure: Literal[EXPOSURES] = "unknown"  # type: ignore[valid-type]
    data_sensitivity: Literal[SENSITIVITIES] = "unknown"  # type: ignore[valid-type]
    tags: list[str] = Field(default=[], max_length=30)


class AssetPatch(BaseModel):
    """Analyst-controlled classification. Tags are free-form labels (max 30, 64 characters each)."""

    name: str | None = Field(default=None, min_length=1, max_length=512)
    description: str | None = None
    environment: Literal[ENVIRONMENTS] | None = None  # type: ignore[valid-type]
    criticality: Literal[CRITICALITIES] | None = None  # type: ignore[valid-type]
    exposure: Literal[EXPOSURES] | None = None  # type: ignore[valid-type]
    data_sensitivity: Literal[SENSITIVITIES] | None = None  # type: ignore[valid-type]
    business_unit: str | None = Field(default=None, max_length=120)
    owner_user_id: uuid.UUID | None = None
    owner_team_id: uuid.UUID | None = None
    tags: list[str] | None = Field(default=None, max_length=30)
    status: Literal["active", "stale", "retired"] | None = None


class RelationshipIn(BaseModel):
    source_asset_id: uuid.UUID
    target_asset_id: uuid.UUID
    type: str
    note: str = Field(default="", max_length=500)


class ScopeIn(BaseModel):
    kind: Literal["domain", "cidr", "url", "path"]
    value: str = Field(min_length=1, max_length=1024)
    allow_active: bool = False
    allow_private_network: bool = False
    authorization_note: str = Field(min_length=10, max_length=2000)
    expires_at: datetime | None = None


def _open_counts(db: Db, asset_ids: list[uuid.UUID]) -> dict[uuid.UUID, int]:
    if not asset_ids:
        return {}
    rows = db.execute(
        select(Finding.asset_id, func.count()).where(Finding.asset_id.in_(asset_ids), Finding.status.in_(OPEN_STATUSES))
        .group_by(Finding.asset_id)
    )
    return dict(rows.all())


def _get(db: Db, asset_id: uuid.UUID) -> Asset:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise NotFound("Asset not found")
    return asset


@router.get("/assets", response_model=Page[AssetOut])
def list_assets(
    db: Db, paging: Paging, _: Principal = require("assets:read"),
    q: str | None = Query(None, max_length=200), type: list[str] | None = Query(None),
    exposure: str | None = None, environment: str | None = None, criticality: str | None = None,
    status: str | None = None, tag: str | None = None, owner_team_id: uuid.UUID | None = None,
    unowned: bool = False, ai_only: bool = False,
    sort: str = "risk_score", order: Literal["asc", "desc"] = "desc",
) -> Page[AssetOut]:
    stmt = select(Asset)
    if q:
        pattern = f"%{like_escape(q)}%"
        stmt = stmt.where(or_(Asset.name.ilike(pattern), Asset.identifier.ilike(pattern)))
    if type:
        stmt = stmt.where(Asset.type.in_(type))
    if ai_only:
        stmt = stmt.where(Asset.type.in_(AI_ASSET_TYPES))
    for column, value in ((Asset.exposure, exposure), (Asset.environment, environment),
                          (Asset.criticality, criticality), (Asset.owner_team_id, owner_team_id)):
        if value:
            stmt = stmt.where(column == value)
    stmt = stmt.where(Asset.status == status) if status else stmt.where(Asset.status != "retired")
    if tag:
        stmt = stmt.where(Asset.tags.any(tag))
    if unowned:
        stmt = stmt.where(Asset.owner_user_id.is_(None), Asset.owner_team_id.is_(None))
    column = SORTABLE.get(sort, Asset.risk_score)
    stmt = stmt.order_by(column.asc() if order == "asc" else column.desc(), Asset.id)
    rows, total = paginate(db, stmt, paging)
    counts = _open_counts(db, [a.id for a in rows])
    items = [AssetOut.model_validate(a).model_copy(update={"open_findings": counts.get(a.id, 0)}) for a in rows]
    return Page(items=items, total=total, page=paging.page, page_size=paging.page_size)


@router.get("/assets/facets")
def asset_facets(db: Db, _: Principal = require("assets:read")) -> dict:
    def group(column):
        return dict(db.execute(select(column, func.count()).where(Asset.status != "retired").group_by(column)).all())

    return {"type": group(Asset.type), "exposure": group(Asset.exposure), "environment": group(Asset.environment),
            "criticality": group(Asset.criticality), "asset_types": list(ASSET_TYPES),
            "relationship_types": list(RELATIONSHIP_TYPES)}


@router.post("/assets", response_model=AssetOut, status_code=201)
def create_asset(body: AssetIn, db: Db, principal: Principal = require("assets:write")) -> AssetOut:
    if body.type not in ASSET_TYPES:
        raise ValidationFailed(f"Unknown asset type {body.type!r}")
    asset, created = upsert_asset(
        db, AssetSpec(type=body.type, identifier=body.identifier, name=body.name, description=body.description,
                      environment=body.environment, exposure=body.exposure, criticality=body.criticality,
                      data_sensitivity=body.data_sensitivity, tags=body.tags),
        source="manual", actor_user_id=principal.user_id,
    )
    if not created:
        raise Conflict("An asset with this type and identifier already exists", details={"asset_id": str(asset.id)})
    audit_event(db, principal, "asset.created", entity_type="asset", entity_id=asset.id,
                data={"type": asset.type, "identifier": asset.identifier})
    return AssetOut.model_validate(asset)


def _row(obj, exclude=("organization_id", "asset_id", "created_at", "updated_at")) -> dict | None:
    if obj is None:
        return None
    return {c.name: getattr(obj, c.name) for c in obj.__table__.columns if c.name not in exclude}


@router.get("/assets/{asset_id}", response_model=AssetDetail)
def get_asset(asset_id: uuid.UUID, db: Db, _: Principal = require("assets:read")) -> AssetDetail:
    asset = _get(db, asset_id)
    by_sev = dict(db.execute(
        select(Finding.severity, func.count()).where(Finding.asset_id == asset.id, Finding.status.in_(OPEN_STATUSES))
        .group_by(Finding.severity)
    ).all())
    detail = AssetDetail.model_validate(asset)
    return detail.model_copy(update={
        "open_findings": sum(by_sev.values()), "findings_by_severity": by_sev,
        "ai": _row(db.get(AIAsset, asset.id)), "agent": _row(db.get(AIAgent, asset.id)),
        "mcp": _row(db.get(MCPServer, asset.id)), "model": _row(db.get(AIModel, asset.id)),
    })


@router.patch("/assets/{asset_id}", response_model=AssetOut)
def update_asset(asset_id: uuid.UUID, body: AssetPatch, db: Db, principal: Principal = require("assets:write")) -> AssetOut:
    asset = _get(db, asset_id)
    changes = body.model_dump(exclude_unset=True)
    if changes.get("owner_user_id") and db.get(User, changes["owner_user_id"]) is None:
        raise ValidationFailed("Owner user does not exist")
    if changes.get("owner_team_id") and db.get(Team, changes["owner_team_id"]) is None:
        raise ValidationFailed("Owner team does not exist")
    diff = {}
    for key, value in changes.items():
        if getattr(asset, key) != value:
            diff[key] = [getattr(asset, key), value]
            setattr(asset, key, value)
    if diff:
        db.add(AssetDiscoveryEvent(
            organization_id=asset.organization_id, asset_id=asset.id, event_type="manual", source="manual",
            actor_user_id=principal.user_id, occurred_at=utcnow(),
            details={k: [str(a) if a is not None else None, str(b) if b is not None else None] for k, (a, b) in diff.items()},
        ))
        audit_event(db, principal, "asset.updated", entity_type="asset", entity_id=asset.id,
                    data={"fields": sorted(diff)})
        if {"exposure", "criticality", "data_sensitivity"} & set(diff):
            from app.domains.risk import service as risk

            for finding in db.execute(select(Finding).where(Finding.asset_id == asset.id,
                                                            Finding.status.in_(OPEN_STATUSES))).scalars():
                risk.score_finding(db, finding, asset)
            db.flush()
            risk.refresh_asset_risk(db, {asset.id})
    db.flush()
    return AssetOut.model_validate(asset)


@router.get("/assets/{asset_id}/history")
def asset_history(asset_id: uuid.UUID, db: Db, paging: Paging, _: Principal = require("assets:read")) -> dict:
    _get(db, asset_id)
    rows, total = paginate(db, select(AssetDiscoveryEvent).where(AssetDiscoveryEvent.asset_id == asset_id)
                           .order_by(AssetDiscoveryEvent.occurred_at.desc()), paging)
    return {"total": total, "page": paging.page, "page_size": paging.page_size, "items": [
        {"id": e.id, "event_type": e.event_type, "source": e.source, "details": e.details,
         "occurred_at": e.occurred_at, "actor_user_id": e.actor_user_id, "job_id": e.job_id} for e in rows]}


def _rel_out(rel: AssetRelationship, assets: dict[uuid.UUID, Asset]) -> dict:
    def brief(aid):
        a = assets.get(aid)
        return {"id": aid, "name": a.name if a else "", "type": a.type if a else "", "exposure": a.exposure if a else "",
                "risk_score": a.risk_score if a else 0}

    return {"id": rel.id, "type": rel.type, "source": brief(rel.source_asset_id), "target": brief(rel.target_asset_id),
            "provenance": rel.source, "confidence": rel.confidence, "evidence": rel.evidence,
            "first_seen_at": rel.first_seen_at, "last_seen_at": rel.last_seen_at}


@router.get("/assets/{asset_id}/relationships")
def asset_relationships(asset_id: uuid.UUID, db: Db, _: Principal = require("assets:read")) -> list[dict]:
    _get(db, asset_id)
    rels = list(db.execute(
        select(AssetRelationship).where(or_(AssetRelationship.source_asset_id == asset_id,
                                            AssetRelationship.target_asset_id == asset_id)).limit(500)
    ).scalars())
    ids = {r.source_asset_id for r in rels} | {r.target_asset_id for r in rels}
    assets = {a.id: a for a in db.execute(select(Asset).where(Asset.id.in_(ids))).scalars()} if ids else {}
    return [_rel_out(r, assets) for r in rels]


@router.post("/asset-relationships", status_code=201)
def create_relationship(body: RelationshipIn, db: Db, principal: Principal = require("assets:write")) -> dict:
    if body.type not in RELATIONSHIP_TYPES:
        raise ValidationFailed(f"Unknown relationship type {body.type!r}")
    if body.source_asset_id == body.target_asset_id:
        raise ValidationFailed("An asset cannot be related to itself")
    source, target = _get(db, body.source_asset_id), _get(db, body.target_asset_id)
    rel = link_assets(db, source, target, body.type, source="manual", confidence=0.8,
                      evidence={"note": body.note, "asserted_by": principal.email})
    audit_event(db, principal, "asset.relationship_created", entity_type="asset_relationship", entity_id=rel.id)
    return _rel_out(rel, {source.id: source, target.id: target})


@router.delete("/asset-relationships/{relationship_id}", status_code=204)
def delete_relationship(relationship_id: uuid.UUID, db: Db, principal: Principal = require("assets:write")) -> None:
    rel = db.get(AssetRelationship, relationship_id)
    if rel is None:
        raise NotFound("Relationship not found")
    db.delete(rel)
    audit_event(db, principal, "asset.relationship_deleted", entity_type="asset_relationship", entity_id=relationship_id)


@router.get("/asset-graph")
def asset_graph(
    db: Db, _: Principal = require("assets:read"), root: uuid.UUID | None = None,
    depth: int = Query(2, ge=1, le=4), limit: int = Query(150, ge=10, le=400),
) -> dict:
    """Neighbourhood of `root` (breadth-first to `depth`), or the highest-risk connected assets."""
    if root is not None:
        _get(db, root)
        seen, frontier, rels = {root}, {root}, {}
        for _hop in range(depth):
            if not frontier or len(seen) >= limit:
                break
            batch = db.execute(
                select(AssetRelationship).where(or_(AssetRelationship.source_asset_id.in_(frontier),
                                                    AssetRelationship.target_asset_id.in_(frontier))).limit(limit * 4)
            ).scalars()
            nxt = set()
            for r in batch:
                rels[r.id] = r
                for aid in (r.source_asset_id, r.target_asset_id):
                    if aid not in seen and len(seen) < limit:
                        seen.add(aid)
                        nxt.add(aid)
            frontier = nxt
        edges = [r for r in rels.values() if r.source_asset_id in seen and r.target_asset_id in seen]
    else:
        edges = list(db.execute(
            select(AssetRelationship).join(Asset, Asset.id == AssetRelationship.source_asset_id)
            .order_by(Asset.risk_score.desc()).limit(limit * 2)
        ).scalars())
        seen = set()
        for r in edges:
            if len(seen) < limit:
                seen.update((r.source_asset_id, r.target_asset_id))
        edges = [r for r in edges if r.source_asset_id in seen and r.target_asset_id in seen]
    assets = list(db.execute(select(Asset).where(Asset.id.in_(seen))).scalars()) if seen else []
    return {
        "nodes": [{"id": a.id, "name": a.name, "type": a.type, "exposure": a.exposure, "criticality": a.criticality,
                   "risk_score": a.risk_score} for a in assets],
        "edges": [{"id": r.id, "source": r.source_asset_id, "target": r.target_asset_id, "type": r.type,
                   "confidence": r.confidence} for r in edges],
    }


@router.get("/scope")
def list_scope(db: Db, _: Principal = require("assets:read")) -> list[dict]:
    rows = db.execute(select(ScopeTarget).order_by(ScopeTarget.kind, ScopeTarget.value)).scalars()
    return [{"id": s.id, "kind": s.kind, "value": s.value, "allow_active": s.allow_active,
             "allow_private_network": s.allow_private_network, "authorization_note": s.authorization_note,
             "authorized_by_user_id": s.authorized_by_user_id, "expires_at": s.expires_at,
             "created_at": s.created_at} for s in rows]


@router.post("/scope", status_code=201)
def add_scope(body: ScopeIn, db: Db, principal: Principal = require("scope:manage")) -> dict:
    value = scope_service.normalize_scope_value(body.kind, body.value)
    if db.execute(select(ScopeTarget.id).where(ScopeTarget.kind == body.kind, ScopeTarget.value == value)).first():
        raise Conflict("This scope entry already exists")
    entry = ScopeTarget(organization_id=principal.organization_id, kind=body.kind, value=value,
                        allow_active=body.allow_active, allow_private_network=body.allow_private_network,
                        authorization_note=body.authorization_note, authorized_by_user_id=principal.user_id,
                        expires_at=body.expires_at)
    db.add(entry)
    db.flush()
    audit_event(db, principal, "scope.added", entity_type="scope_target", entity_id=entry.id,
                data={"kind": body.kind, "value": value, "allow_active": body.allow_active,
                      "allow_private_network": body.allow_private_network, "note": body.authorization_note})
    return {"id": entry.id, "kind": entry.kind, "value": entry.value}


@router.delete("/scope/{scope_id}", status_code=204)
def remove_scope(scope_id: uuid.UUID, db: Db, principal: Principal = require("scope:manage")) -> None:
    entry = db.get(ScopeTarget, scope_id)
    if entry is None:
        raise NotFound("Scope entry not found")
    db.delete(entry)
    audit_event(db, principal, "scope.removed", entity_type="scope_target", entity_id=scope_id,
                data={"kind": entry.kind, "value": entry.value})
