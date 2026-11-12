"""Dashboard metrics. Every number is computed from the tenant's data at request time."""

from fastapi import APIRouter, Query
from sqlalchemy import and_, func, or_, select, text

from app.api.deps import Db, Principal, require
from app.db.base import utcnow
from app.models import (
    AIAsset,
    AIFinding,
    AIIntegration,
    Assessment,
    AssessmentRun,
    Asset,
    AttackPath,
    Finding,
    Policy,
    PolicyEvaluation,
    RemediationTask,
    Vulnerability,
)
from app.models.asset import AI_ASSET_TYPES
from app.models.finding import AI_DOMAINS, OPEN_STATUSES

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])
OPEN = Finding.status.in_(OPEN_STATUSES)
ACTIVE = Asset.status != "retired"


def _count(db: Db, *where, model=Finding) -> int:
    return db.execute(select(func.count()).select_from(model).where(*where)).scalar_one()


def _group(db: Db, column, *where) -> dict:
    return dict(db.execute(select(column, func.count()).where(*where).group_by(column)).all())


def _trend(db: Db, days: int) -> list[dict]:
    rows = db.execute(text(
        """
        SELECT d::date AS day,
          (SELECT count(*) FROM findings f WHERE f.first_seen_at::date = d::date) AS opened,
          (SELECT count(*) FROM findings f WHERE f.resolved_at::date = d::date) AS resolved,
          (SELECT count(*) FROM findings f WHERE f.first_seen_at < d + interval '1 day'
                 AND (f.resolved_at IS NULL OR f.resolved_at >= d + interval '1 day')) AS open_total,
          (SELECT count(*) FROM findings f WHERE f.first_seen_at < d + interval '1 day'
                 AND (f.resolved_at IS NULL OR f.resolved_at >= d + interval '1 day')
                 AND f.risk_level IN ('critical', 'high')) AS open_high_risk
        FROM generate_series(date_trunc('day', now()) - make_interval(days => :days - 1), date_trunc('day', now()), '1 day') d
        ORDER BY d
        """), {"days": days}).all()
    return [{"day": r.day.isoformat(), "opened": r.opened, "resolved": r.resolved, "open_total": r.open_total,
             "open_high_risk": r.open_high_risk} for r in rows]


def _compliance(db: Db) -> dict:
    latest = (select(PolicyEvaluation.policy_id, func.max(PolicyEvaluation.evaluated_at).label("at"))
              .group_by(PolicyEvaluation.policy_id).subquery())
    rows = db.execute(
        select(PolicyEvaluation.status, func.count())
        .join(latest, and_(latest.c.policy_id == PolicyEvaluation.policy_id, latest.c.at == PolicyEvaluation.evaluated_at))
        .join(Policy, Policy.id == PolicyEvaluation.policy_id).where(Policy.enabled).group_by(PolicyEvaluation.status)
    ).all()
    by = dict(rows)
    applicable = by.get("compliant", 0) + by.get("non_compliant", 0)
    return {"compliant": by.get("compliant", 0), "non_compliant": by.get("non_compliant", 0),
            "not_applicable": by.get("not_applicable", 0),
            "percent": round(100 * by.get("compliant", 0) / applicable, 1) if applicable else None}


@router.get("/overview")
def overview(db: Db, _: Principal = require("findings:read", "assets:read"), trend_days: int = Query(30, ge=7, le=180)) -> dict:
    now = utcnow()
    exploitable = db.execute(
        select(func.count()).select_from(Finding).join(Vulnerability, Vulnerability.id == Finding.vulnerability_id)
        .where(OPEN, or_(Vulnerability.kev.is_(True), Vulnerability.exploit_available.is_(True)))
    ).scalar_one()
    unmanaged_ai = db.execute(
        select(func.count()).select_from(Asset).outerjoin(AIAsset, AIAsset.asset_id == Asset.id)
        .where(ACTIVE, Asset.type.in_(AI_ASSET_TYPES),
               or_(AIAsset.approval_status.in_(("unapproved", "unknown")), AIAsset.asset_id.is_(None),
                   and_(Asset.owner_user_id.is_(None), Asset.owner_team_id.is_(None))))
    ).scalar_one()
    top_assets = db.execute(select(Asset).where(ACTIVE, Asset.risk_score > 0).order_by(Asset.risk_score.desc()).limit(8)).scalars()
    top_findings = db.execute(select(Finding, Asset.name).join(Asset, Asset.id == Finding.asset_id).where(OPEN)
                              .order_by(Finding.risk_score.desc()).limit(8)).all()
    recent_runs = db.execute(select(AssessmentRun, Assessment.name, Assessment.kind)
                             .join(Assessment, Assessment.id == AssessmentRun.assessment_id)
                             .order_by(AssessmentRun.created_at.desc()).limit(8)).all()
    cloud_open = _group(db, Finding.severity, OPEN, Finding.domain.in_(("cloud", "identity")))
    ai_open = _group(db, Finding.risk_level, OPEN, Finding.domain.in_(AI_DOMAINS))
    return {
        "generated_at": now,
        "assets": {"total": _count(db, ACTIVE, model=Asset),
                   "internet_exposed": _count(db, ACTIVE, Asset.exposure == "internet", model=Asset),
                   "unowned": _count(db, ACTIVE, Asset.owner_user_id.is_(None), Asset.owner_team_id.is_(None), model=Asset),
                   "by_type": _group(db, Asset.type, ACTIVE)},
        "findings": {"open": _count(db, OPEN), "critical": _count(db, OPEN, Finding.risk_level == "critical"),
                     "high": _count(db, OPEN, Finding.risk_level == "high"), "exploitable": exploitable,
                     "by_risk_level": _group(db, Finding.risk_level, OPEN), "by_domain": _group(db, Finding.domain, OPEN),
                     "by_status": _group(db, Finding.status)},
        "attack_paths": {"active": _count(db, AttackPath.status == "active", model=AttackPath),
                         "high_risk": _count(db, AttackPath.status == "active", AttackPath.severity.in_(("critical", "high")), model=AttackPath),
                         "by_classification": _group(db, AttackPath.classification, AttackPath.status == "active")},
        "cloud": {"accounts": _count(db, ACTIVE, Asset.type == "cloud_account", model=Asset),
                  "resources": _count(db, ACTIVE, Asset.type.in_(("cloud_resource", "storage", "database", "load_balancer", "identity")),
                                      Asset.identifier.like("arn:%"), model=Asset),
                  "open_findings_by_severity": cloud_open},
        "ai": {"assets": _count(db, ACTIVE, Asset.type.in_(AI_ASSET_TYPES), model=Asset), "unmanaged": unmanaged_ai,
               "open_findings_by_risk_level": ai_open,
               "agent_permission_risks": _count(db, OPEN, Finding.domain == "ai_agent")},
        "remediation": {"open_tasks": _count(db, RemediationTask.status.in_(("open", "in_progress", "pending_validation")), model=RemediationTask),
                        "overdue_slas": _count(db, OPEN, Finding.due_at < now),
                        "pending_validation": _count(db, Finding.status == "pending_validation"),
                        "unassigned_high_risk": _count(db, OPEN, Finding.risk_level.in_(("critical", "high")),
                                                       Finding.owner_user_id.is_(None), Finding.owner_team_id.is_(None))},
        "compliance": _compliance(db),
        "trend": _trend(db, trend_days),
        "top_assets": [{"id": a.id, "name": a.name, "type": a.type, "risk_score": a.risk_score, "exposure": a.exposure} for a in top_assets],
        "top_findings": [{"id": f.id, "title": f.title, "risk_score": f.risk_score, "risk_level": f.risk_level,
                          "asset_name": name, "domain": f.domain} for f, name in top_findings],
        "recent_runs": [{"id": r.id, "assessment_id": r.assessment_id, "name": name, "kind": kind, "status": r.status,
                         "created_at": r.created_at, "dry_run": r.dry_run,
                         "findings_created": (r.summary or {}).get("findings_created")} for r, name, kind in recent_runs],
    }


@router.get("/ai")
def ai_overview(db: Db, _: Principal = require("ai:read")) -> dict:
    ai_open = and_(OPEN, Finding.domain.in_(AI_DOMAINS))
    public_endpoints = db.execute(
        select(func.count()).select_from(Asset)
        .where(ACTIVE, Asset.type.in_(("llm_endpoint", "ai_application", "mcp_server", "vector_database", "rag_application")),
               Asset.exposure == "internet")).scalar_one()
    unapproved_providers = db.execute(
        select(AIAsset.provider, func.count()).join(Asset, Asset.id == AIAsset.asset_id)
        .where(ACTIVE, AIAsset.provider.isnot(None), AIAsset.approval_status == "unapproved")
        .group_by(AIAsset.provider)).all()
    owasp = db.execute(select(AIFinding.owasp_llm, func.count()).join(Finding, Finding.id == AIFinding.finding_id)
                       .where(OPEN, AIFinding.owasp_llm.isnot(None)).group_by(AIFinding.owasp_llm)).all()
    status = _group(db, Finding.status, Finding.domain.in_(AI_DOMAINS))
    vulnerable_frameworks = db.execute(
        select(func.count(func.distinct(Finding.asset_id))).join(Asset, Asset.id == Finding.asset_id)
        .where(OPEN, Finding.vulnerability_id.isnot(None), Asset.type == "package",
               Asset.attributes["ai_related"].as_boolean().is_(True))).scalar_one()
    top = db.execute(select(Finding, Asset.name).join(Asset, Asset.id == Finding.asset_id).where(ai_open)
                     .order_by(Finding.risk_score.desc()).limit(10)).all()
    return {
        "assets": {"total": _count(db, ACTIVE, Asset.type.in_(AI_ASSET_TYPES), model=Asset),
                   "by_type": _group(db, Asset.type, ACTIVE, Asset.type.in_(AI_ASSET_TYPES)),
                   "public_endpoints": public_endpoints,
                   "without_owner": _count(db, ACTIVE, Asset.type.in_(AI_ASSET_TYPES), Asset.owner_user_id.is_(None),
                                           Asset.owner_team_id.is_(None), model=Asset),
                   "agents": _count(db, ACTIVE, Asset.type == "ai_agent", model=Asset),
                   "mcp_servers": _count(db, ACTIVE, Asset.type == "mcp_server", model=Asset),
                   "models": _count(db, ACTIVE, Asset.type == "ai_model", model=Asset),
                   "integrations_detected": _count(db, model=AIIntegration)},
        "by_approval_status": dict(db.execute(
            select(AIAsset.approval_status, func.count()).join(Asset, Asset.id == AIAsset.asset_id).where(ACTIVE)
            .group_by(AIAsset.approval_status)).all()),
        "unapproved_providers": [{"provider": p, "assets": c} for p, c in unapproved_providers],
        "findings": {"open": _count(db, ai_open), "critical_llm": _count(db, OPEN, Finding.domain == "ai_llm", Finding.risk_level == "critical"),
                     "by_domain": _group(db, Finding.domain, ai_open), "by_risk_level": _group(db, Finding.risk_level, ai_open),
                     "by_owasp_llm": dict(owasp), "agents_excessive_permissions": _count(db, OPEN, Finding.domain == "ai_agent"),
                     "mcp": _count(db, OPEN, Finding.domain == "ai_mcp"), "rag": _count(db, OPEN, Finding.domain == "ai_rag"),
                     "model_supply_chain": _count(db, OPEN, Finding.domain == "ai_model"),
                     "shadow_ai": _count(db, OPEN, Finding.domain == "shadow_ai"),
                     "vulnerable_ai_frameworks": vulnerable_frameworks},
        "attack_paths": _count(db, AttackPath.status == "active", AttackPath.involves_ai.is_(True), model=AttackPath),
        "remediation_status": status,
        "top_findings": [{"id": f.id, "title": f.title, "risk_score": f.risk_score, "risk_level": f.risk_level,
                          "domain": f.domain, "asset_name": name} for f, name in top],
    }
