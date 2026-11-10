"""Asset inventory operations shared by the API and all discovery engines."""

import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.db.session import org_of
from app.models import AIAsset, Asset, AssetDiscoveryEvent, AssetRelationship
from app.models.asset import AI_ASSET_TYPES, ASSET_TYPES, RELATIONSHIP_TYPES

_CASE_INSENSITIVE = {"domain", "subdomain", "website", "dns_record", "ip_address", "certificate"}
# Attributes whose change is worth recording in asset history.
_EXPOSURE_RANK = {"unknown": 0, "private": 1, "internal": 2, "internet": 3}


def canonical_identifier(asset_type: str, identifier: str) -> str:
    identifier = identifier.strip()
    if asset_type in _CASE_INSENSITIVE:
        identifier = identifier.lower().rstrip(".")
    return identifier[:1024]


@dataclass
class AssetSpec:
    type: str
    identifier: str
    name: str | None = None
    description: str | None = None
    environment: str | None = None
    exposure: str | None = None
    criticality: str | None = None
    data_sensitivity: str | None = None
    attributes: dict = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    ai: dict | None = None  # AIAsset column values; creates/updates the AI extension row


def guess_environment(identifier: str) -> str | None:
    lowered = identifier.lower()
    for marker, env in (("staging", "staging"), ("stage.", "staging"), ("stg", "staging"), ("dev.", "development"),
                        ("-dev", "development"), ("test.", "test"), ("-test", "test"), ("qa.", "test"),
                        ("uat", "staging"), ("sandbox", "development")):
        if marker in lowered:
            return env
    return None


def upsert_asset(
    db: Session, spec: AssetSpec, *, source: str, job_id: uuid.UUID | None = None,
    actor_user_id: uuid.UUID | None = None,
) -> tuple[Asset, bool]:
    """Create or update an asset by canonical (type, identifier). Returns (asset, created).

    Discovery never lowers exposure and never overwrites analyst-set classification
    (environment, criticality, sensitivity); it only fills values that are still unknown.
    """
    if spec.type not in ASSET_TYPES:
        raise ValueError(f"Unknown asset type {spec.type!r}")
    org_id = org_of(db)
    identifier = canonical_identifier(spec.type, spec.identifier)
    now = utcnow()
    asset = db.execute(
        select(Asset).where(Asset.type == spec.type, Asset.identifier == identifier)
    ).scalar_one_or_none()
    created = asset is None
    changes: dict = {}
    if asset is None:
        asset = Asset(
            organization_id=org_id, type=spec.type, identifier=identifier, name=(spec.name or identifier)[:512],
            description=spec.description or "",
            environment=spec.environment or guess_environment(identifier) or "unknown",
            exposure=spec.exposure or "unknown", criticality=spec.criticality or "medium",
            data_sensitivity=spec.data_sensitivity or "unknown", attributes=dict(spec.attributes),
            tags=sorted(set(spec.tags)), discovery_sources=[source], first_seen_at=now, last_seen_at=now,
        )
        db.add(asset)
        db.flush()
    else:
        if spec.exposure and _EXPOSURE_RANK[spec.exposure] > _EXPOSURE_RANK.get(asset.exposure, 0):
            changes["exposure"] = [asset.exposure, spec.exposure]
            asset.exposure = spec.exposure
        if spec.environment and asset.environment == "unknown":
            asset.environment = spec.environment
        if spec.data_sensitivity and asset.data_sensitivity == "unknown":
            asset.data_sensitivity = spec.data_sensitivity
        if spec.name and asset.name == asset.identifier and spec.name != asset.name:
            asset.name = spec.name[:512]
        if spec.attributes:
            merged = dict(asset.attributes or {})
            for key, value in spec.attributes.items():
                if merged.get(key) != value:
                    if key in merged:
                        changes.setdefault("attributes", {})[key] = [merged.get(key), value]
                    merged[key] = value
            asset.attributes = merged
        if spec.tags:
            asset.tags = sorted(set(asset.tags) | set(spec.tags))
        if source not in asset.discovery_sources:
            asset.discovery_sources = [*asset.discovery_sources, source]
        if asset.status == "stale":
            asset.status = "active"
            changes["status"] = ["stale", "active"]
        asset.last_seen_at = now
    if spec.ai is not None or spec.type in AI_ASSET_TYPES:
        ai_row = db.get(AIAsset, asset.id)
        if ai_row is None:
            ai_row = AIAsset(organization_id=org_id, asset_id=asset.id)
            db.add(ai_row)
        for key, value in (spec.ai or {}).items():
            if value is not None and getattr(ai_row, key) in (None, "unknown", False) and getattr(ai_row, key) != value:
                setattr(ai_row, key, value)
    if created or changes:
        db.add(AssetDiscoveryEvent(
            organization_id=org_id, asset_id=asset.id, event_type="discovered" if created else "changed",
            source=source, job_id=job_id, actor_user_id=actor_user_id, details=changes, occurred_at=now,
        ))
        if changes.get("exposure", [None, None])[1] == "internet":
            from app.domains.notifications.service import notify

            notify(db, organization_id=org_id, event_type="asset.exposed", severity="high",
                   title=f"Asset is now internet-exposed: {asset.name}", entity_type="asset", entity_id=asset.id)
    db.flush()
    return asset, created


def link_assets(
    db: Session, source_asset: Asset, target_asset: Asset, rel_type: str, *, source: str,
    evidence: dict | None = None, confidence: float = 1.0,
) -> AssetRelationship:
    if rel_type not in RELATIONSHIP_TYPES:
        raise ValueError(f"Unknown relationship type {rel_type!r}")
    if source_asset.id == target_asset.id:
        raise ValueError("An asset cannot be related to itself")
    now = utcnow()
    rel = db.execute(
        select(AssetRelationship).where(
            AssetRelationship.source_asset_id == source_asset.id,
            AssetRelationship.target_asset_id == target_asset.id, AssetRelationship.type == rel_type,
        )
    ).scalar_one_or_none()
    if rel is None:
        rel = AssetRelationship(
            organization_id=org_of(db), source_asset_id=source_asset.id, target_asset_id=target_asset.id,
            type=rel_type, source=source, confidence=confidence, evidence=evidence or {}, first_seen_at=now,
            last_seen_at=now,
        )
        db.add(rel)
    else:
        rel.last_seen_at = now
        rel.confidence = max(rel.confidence, confidence)
        if evidence:
            rel.evidence = {**(rel.evidence or {}), **evidence}
    db.flush()
    return rel
