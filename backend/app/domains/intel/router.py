import uuid

from fastapi import APIRouter, Query
from sqlalchemy import func, or_, select

from app.api.deps import Db, Paging, Principal, audit_event, like_escape, paginate, require
from app.core.errors import NotFound, ValidationFailed
from app.integrations.intel import sources
from app.models import (
    AIFinding,
    Asset,
    AttackPath,
    AttackPathEdge,
    Finding,
    IntelSyncState,
    ThreatIntelligence,
    Vulnerability,
)
from app.models.finding import OPEN_STATUSES
from app.workers.queue import JobContext, enqueue, job_handler

router = APIRouter(prefix="/intel", tags=["Threat Intelligence"])


@job_handler("intel.sync")
def sync_job(job: JobContext, db) -> dict:
    """Synchronise the requested sources, then rescore this organization's findings."""
    wanted = job.config.get("sources") or ["cisa_kev", "epss"]
    results, failures = {}, {}
    for index, source in enumerate(wanted):
        job.progress(int(100 * index / len(wanted)), f"Synchronising {source}")
        try:
            results[source] = sources.run_sync(db, source)
        except Exception as exc:  # one failing source must not prevent the others
            failures[source] = f"{type(exc).__name__}: {exc}"[:300]
    if failures and not results:
        raise RuntimeError(f"All sources failed: {failures}")
    from app.domains.risk import service as risk

    rescored = risk.recalculate_all(db, job.organization_id)
    return {"results": results, "failures": failures, "findings_rescored": rescored["changed"]}


def _vuln_out(v: Vulnerability, affected_assets: int | None = None) -> dict:
    return {"id": v.id, "external_id": v.external_id, "aliases": v.aliases, "source": v.source, "title": v.title,
            "description": v.description, "cvss_score": v.cvss_score, "cvss_vector": v.cvss_vector,
            "cvss_version": v.cvss_version, "cwe_ids": v.cwe_ids, "epss_score": v.epss_score,
            "epss_percentile": v.epss_percentile, "kev": v.kev, "kev_date_added": v.kev_date_added,
            "kev_due_date": v.kev_due_date, "kev_ransomware_use": v.kev_ransomware_use,
            "exploit_available": v.exploit_available, "fixed_versions": v.fixed_versions, "references": v.references,
            "published_at": v.published_at, "modified_at": v.modified_at, "affected_assets": affected_assets}


@router.get("/vulnerabilities")
def list_vulnerabilities(
    db: Db, paging: Paging, _: Principal = require("intel:read"), q: str | None = Query(None, max_length=120),
    kev: bool = False, affecting_only: bool = True,
) -> dict:
    """Vulnerability catalogue. By default only vulnerabilities that affect this organization's assets."""
    affected = (select(Finding.vulnerability_id, func.count(func.distinct(Finding.asset_id)).label("assets"))
                .where(Finding.status.in_(OPEN_STATUSES), Finding.vulnerability_id.isnot(None))
                .group_by(Finding.vulnerability_id).subquery())
    stmt = select(Vulnerability, affected.c.assets)
    stmt = stmt.join(affected, affected.c.vulnerability_id == Vulnerability.id) if affecting_only else stmt.outerjoin(
        affected, affected.c.vulnerability_id == Vulnerability.id)
    if q:
        pattern = f"%{like_escape(q)}%"
        stmt = stmt.where(or_(Vulnerability.external_id.ilike(pattern), Vulnerability.title.ilike(pattern)))
    if kev:
        stmt = stmt.where(Vulnerability.kev.is_(True))
    stmt = stmt.order_by(Vulnerability.kev.desc(), Vulnerability.epss_score.desc().nulls_last(),
                         Vulnerability.cvss_score.desc().nulls_last(), Vulnerability.external_id)
    rows, total = paginate(db, stmt, paging, scalars=False)
    return {"items": [_vuln_out(v, n or 0) for v, n in rows], "total": total, "page": paging.page, "page_size": paging.page_size}


@router.get("/vulnerabilities/{vulnerability_id}")
def get_vulnerability(vulnerability_id: uuid.UUID, db: Db, _: Principal = require("intel:read")) -> dict:
    v = db.get(Vulnerability, vulnerability_id)
    if v is None:
        raise NotFound("Vulnerability not found")
    rows = db.execute(select(Finding, Asset).join(Asset, Asset.id == Finding.asset_id)
                      .where(Finding.vulnerability_id == v.id).order_by(Finding.risk_score.desc()).limit(200)).all()
    return {**_vuln_out(v, len({a.id for _, a in rows})),
            "findings": [{"id": f.id, "title": f.title, "status": f.status, "risk_score": f.risk_score,
                          "risk_level": f.risk_level, "asset_id": a.id, "asset_name": a.name, "asset_exposure": a.exposure}
                         for f, a in rows]}


@router.get("/items")
def list_intel(db: Db, paging: Paging, _: Principal = require("intel:read"), source: str | None = None,
               kind: str | None = None, q: str | None = Query(None, max_length=120)) -> dict:
    stmt = select(ThreatIntelligence).order_by(ThreatIntelligence.published_at.desc().nulls_last(), ThreatIntelligence.external_id)
    if source:
        stmt = stmt.where(ThreatIntelligence.source == source)
    if kind:
        stmt = stmt.where(ThreatIntelligence.kind == kind)
    if q:
        pattern = f"%{like_escape(q)}%"
        stmt = stmt.where(or_(ThreatIntelligence.title.ilike(pattern), ThreatIntelligence.external_id.ilike(pattern)))
    rows, total = paginate(db, stmt, paging)
    return {"total": total, "page": paging.page, "page_size": paging.page_size, "items": [
        {"id": t.id, "source": t.source, "external_id": t.external_id, "kind": t.kind, "title": t.title,
         "description": t.description[:1500], "confidence": t.confidence, "source_url": t.source_url,
         "published_at": t.published_at, "fetched_at": t.fetched_at, "data": t.data, "references": t.references} for t in rows]}


@router.get("/technique-exposure")
def technique_exposure(db: Db, _: Principal = require("intel:read")) -> list[dict]:
    """Threat-to-exposure correlation: techniques that appear on this organization's active
    attack paths or are mapped to its open AI findings, with catalogue names where synchronised."""
    path_rows = db.execute(
        select(AttackPathEdge.technique, func.count(func.distinct(AttackPathEdge.attack_path_id)))
        .join(AttackPath, AttackPath.id == AttackPathEdge.attack_path_id)
        .where(AttackPath.status == "active", AttackPathEdge.technique.isnot(None)).group_by(AttackPathEdge.technique)).all()
    finding_rows = db.execute(
        select(AIFinding.atlas_technique, func.count()).join(Finding, Finding.id == AIFinding.finding_id)
        .where(Finding.status.in_(OPEN_STATUSES), AIFinding.atlas_technique.isnot(None)).group_by(AIFinding.atlas_technique)).all()
    merged: dict[str, dict] = {}
    for technique, count in path_rows:
        merged.setdefault(technique, {"technique": technique, "attack_paths": 0, "findings": 0})["attack_paths"] = count
    for technique, count in finding_rows:
        merged.setdefault(technique, {"technique": technique, "attack_paths": 0, "findings": 0})["findings"] = count
    names = {t.external_id: t for t in db.execute(
        select(ThreatIntelligence).where(ThreatIntelligence.external_id.in_(merged))).scalars()} if merged else {}
    for technique, row in merged.items():
        info = names.get(technique)
        row.update({"name": info.title if info else None, "source": info.source if info else None,
                    "url": info.source_url if info else None})
    return sorted(merged.values(), key=lambda r: (-r["attack_paths"], -r["findings"]))


@router.get("/sources")
def list_sources(db: Db, _: Principal = require("intel:read")) -> list[dict]:
    states = {s.source: s for s in db.execute(select(IntelSyncState)).scalars()}
    counts = dict(db.execute(select(ThreatIntelligence.source, func.count()).group_by(ThreatIntelligence.source)).all())
    out = []
    for source in [*sources.SOURCES, "osv"]:
        s = states.get(source)
        out.append({"source": source, "syncable": source in sources.SOURCES, "last_success_at": s.last_success_at if s else None,
                    "last_attempt_at": s.last_attempt_at if s else None, "last_error": s.last_error if s else None,
                    "records": s.records if s else 0, "intel_items": counts.get(source, 0)})
    return out


@router.post("/sync", status_code=202)
def trigger_sync(db: Db, principal: Principal = require("intel:sync"), source: list[str] = Query(default=["cisa_kev", "epss"])) -> dict:
    unknown = set(source) - set(sources.SOURCES)
    if unknown:
        raise ValidationFailed(f"Unknown sources: {sorted(unknown)}", details={"sources": sorted(sources.SOURCES)})
    job = enqueue(db, organization_id=principal.organization_id, job_type="intel.sync", config={"sources": source},
                  idempotency_key="intel.sync:" + ",".join(sorted(source)), created_by_user_id=principal.user_id)
    audit_event(db, principal, "intel.sync_requested", entity_type="job", entity_id=job.id, data={"sources": source})
    return {"job_id": job.id, "state": job.state}
