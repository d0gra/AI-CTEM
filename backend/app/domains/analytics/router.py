import uuid

from fastapi import APIRouter
from sqlalchemy import select

from app.api.deps import Db, Principal, audit_event, require
from app.core.errors import NotFound, ValidationFailed
from app.domains.analytics import service
from app.models import AIFinding, Asset, AttackPath, Evidence, Finding, Integration, Vulnerability

router = APIRouter(prefix="/analytics", tags=["AI-assisted analysis"])


@router.get("/settings")
def get_settings_(db: Db, principal: Principal = require("ai_analytics:use")) -> dict:
    return {**service.load_settings(db, principal.organization_id).model_dump(mode="json"), "usage_this_month": service.month_usage(db),
            "prompt_version": service.PROMPT_VERSION}


@router.put("/settings")
def put_settings(body: service.AnalyticsSettings, db: Db, principal: Principal = require("admin:org")) -> dict:
    if body.enabled:
        integration = db.get(Integration, body.integration_id) if body.integration_id else None
        if integration is None or integration.connector != "llm":
            raise ValidationFailed("Select an LLM endpoint integration as the analysis provider")
    service.save_settings(db, principal.organization_id, body)
    audit_event(db, principal, "ai_analytics.settings_updated", data=body.model_dump(mode="json"))
    return body.model_dump(mode="json")


@router.post("/findings/{finding_id}/explain")
def explain_finding(finding_id: uuid.UUID, db: Db, principal: Principal = require("ai_analytics:use", "findings:read")) -> dict:
    f = db.get(Finding, finding_id)
    if f is None:
        raise NotFound("Finding not found")
    asset = db.get(Asset, f.asset_id)
    vuln = db.get(Vulnerability, f.vulnerability_id) if f.vulnerability_id else None
    ai = db.get(AIFinding, f.id)
    evidence = db.execute(select(Evidence).where(Evidence.finding_id == f.id).limit(3)).scalars()
    facts = {
        "finding": {"title": f.title, "description": f.description[:4000], "severity": f.severity, "confidence": f.confidence,
                    "status": f.status, "domain": f.domain, "source": f.source, "risk_score": f.risk_score, "risk_level": f.risk_level,
                    "remediation_guidance": f.remediation[:2000], "technical_impact": f.technical_impact, "first_seen": f.first_seen_at,
                    "due": f.due_at},
        "asset": {"name": asset.name, "type": asset.type, "exposure": asset.exposure, "criticality": asset.criticality,
                  "environment": asset.environment, "data_sensitivity": asset.data_sensitivity} if asset else None,
        "vulnerability": {"id": vuln.external_id, "cvss": vuln.cvss_score, "epss": vuln.epss_score, "epss_percentile": vuln.epss_percentile,
                          "known_exploited": vuln.kev, "fixed_versions": vuln.fixed_versions} if vuln else None,
        "ai_taxonomy": {"owasp_llm": ai.owasp_llm, "atlas_technique": ai.atlas_technique} if ai else None,
        "evidence": [{"kind": e.kind, "summary": e.summary, "content": e.content} for e in evidence],
    }
    result = service.analyse(db, principal, purpose="Explain this finding and how to remediate it", entity_type="finding",
                             entity_id=f.id, facts=facts)
    audit_event(db, principal, "ai_analytics.used", entity_type="finding", entity_id=f.id,
                data={"model": result["model"], "evidence_shared": result["evidence_shared"]})
    return result


@router.post("/attack-paths/{path_id}/explain")
def explain_path(path_id: uuid.UUID, db: Db, principal: Principal = require("ai_analytics:use", "attack_paths:read")) -> dict:
    p = db.get(AttackPath, path_id)
    if p is None:
        raise NotFound("Attack path not found")
    facts = {"attack_path": {"title": p.title, "classification": p.classification, "confidence": p.confidence, "severity": p.severity,
                             "score": p.score, "business_impact": p.business_impact, "involves_ai": p.involves_ai},
             "steps": p.required_conditions, "nodes": [{"label": n.label, "type": n.node_type, "trust_boundary": n.crosses_trust_boundary} for n in p.nodes],
             "edges": [{"relationship": e.relationship_type, "technique": e.technique, "evidence_level": e.evidence_level} for e in p.edges],
             "remediation_opportunities": p.remediation_opportunities}
    result = service.analyse(db, principal, purpose="Explain this attack path and the most effective place to break it",
                             entity_type="attack_path", entity_id=p.id, facts=facts)
    audit_event(db, principal, "ai_analytics.used", entity_type="attack_path", entity_id=p.id, data={"model": result["model"]})
    return result
