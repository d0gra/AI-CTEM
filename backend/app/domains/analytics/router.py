import json
import uuid
from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.deps import Db, Principal, audit_event, require
from app.core.config import get_settings
from app.core.errors import NotFound, UpstreamError, ValidationFailed
from app.core.security import decrypt_secret, encrypt_secret
from app.db.base import utcnow
from app.domains.analytics import service
from app.integrations.base import ApiError
from app.integrations.llm import claude
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
        if integration is None or integration.connector not in ("claude", "llm"):
            raise ValidationFailed("Connect Claude, or select a model endpoint integration, as the analysis provider")
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


# --- Claude connection ---------------------------------------------------------------------

class ClaudeConnectIn(BaseModel):
    credential_source: Literal["api_key", "server"] = "api_key"
    api_key: str | None = Field(default=None, max_length=400, description="Omit to keep the stored key when updating")
    model: str = Field(default=claude.DEFAULT_MODEL, min_length=3, max_length=120)
    effort: Literal["low", "medium", "high"] = "medium"


def _claude_integration(db: Db) -> Integration | None:
    return db.execute(select(Integration).where(Integration.connector == "claude")).scalars().first()


def _claude_status(db: Db, principal: Principal, integration: Integration | None) -> dict:
    settings = service.load_settings(db, principal.organization_id)
    base = {"server_credentials_allowed": get_settings().allow_server_claude_credentials, "default_model": claude.DEFAULT_MODEL,
            "billing_note": "Usage is billed to a Claude Console organization (platform.claude.com). "
                            "Claude Pro, Max and Team plans do not include API access."}
    if integration is None:
        return {**base, "connected": False}
    config = claude.ClaudeConfig.model_validate(integration.config)
    return {**base, "connected": True, "integration_id": integration.id, "credential_source": config.credential_source,
            "has_api_key": bool(integration.credentials_encrypted), "model": config.model, "effort": config.effort,
            "health": integration.health, "last_checked_at": integration.last_checked_at, "last_error": integration.last_error,
            "in_use": settings.enabled and settings.integration_id == integration.id}


@router.get("/claude")
def claude_status(db: Db, principal: Principal = require("ai_analytics:use")) -> dict:
    return _claude_status(db, principal, _claude_integration(db))


@router.post("/claude/connect")
def claude_connect(body: ClaudeConnectIn, db: Db, principal: Principal = require("admin:org")) -> dict:
    """Validate the credential against the Claude Models API, store it, and enable AI analysis with it."""
    integration = _claude_integration(db)
    stored = json.loads(decrypt_secret(integration.credentials_encrypted)) if integration and integration.credentials_encrypted else {}
    key = (body.api_key or "").strip() or (stored.get("api_key", "") if body.credential_source == "api_key" else "")
    if body.credential_source == "api_key" and not key:
        raise ValidationFailed("Enter an API key from platform.claude.com/settings/keys")
    config = claude.ClaudeConfig(credential_source=body.credential_source, model=body.model, effort=body.effort)
    credentials = claude.ClaudeCredentials(api_key=key if body.credential_source == "api_key" else "")
    result = claude.test_claude(config, credentials)
    if not result.ok:
        audit_event(db, principal, "ai_analytics.claude_connect_failed", outcome="failure", data={"error_class": result.error_class,
                                                                                               "source": body.credential_source})
        raise ValidationFailed(result.detail, details={"error_class": result.error_class, "models": result.metadata.get("models", [])})
    if integration is None:
        integration = Integration(organization_id=principal.organization_id, connector="claude", name="Claude")
        db.add(integration)
    integration.config = config.model_dump()
    integration.credentials_encrypted = encrypt_secret(json.dumps({"api_key": key})) if body.credential_source == "api_key" else None
    integration.enabled, integration.health, integration.last_checked_at = True, "healthy", utcnow()
    integration.last_error = integration.last_error_class = None
    db.flush()
    settings = service.load_settings(db, principal.organization_id)
    settings.enabled, settings.integration_id = True, integration.id
    service.save_settings(db, principal.organization_id, settings)
    audit_event(db, principal, "ai_analytics.claude_connected", entity_type="integration", entity_id=integration.id,
                data={"source": body.credential_source, "model": body.model, "key_replaced": bool(body.api_key)})
    return {**_claude_status(db, principal, integration), "models": result.metadata["models"]}


@router.get("/claude/models")
def claude_models(db: Db, principal: Principal = require("ai_analytics:use")) -> list[dict]:
    integration = _claude_integration(db)
    if integration is None:
        raise NotFound("Claude is not connected")
    secrets = json.loads(decrypt_secret(integration.credentials_encrypted)) if integration.credentials_encrypted else {}
    try:
        return claude.list_models(claude.make_client(claude.ClaudeConfig.model_validate(integration.config),
                                                     claude.ClaudeCredentials.model_validate(secrets)))
    except ApiError as exc:
        raise UpstreamError(str(exc), details={"error_class": exc.error_class}) from exc


@router.post("/claude/test")
def claude_test(db: Db, principal: Principal = require("ai_analytics:use")) -> dict:
    integration = _claude_integration(db)
    if integration is None:
        raise NotFound("Claude is not connected")
    secrets = json.loads(decrypt_secret(integration.credentials_encrypted)) if integration.credentials_encrypted else {}
    result = claude.test_claude(claude.ClaudeConfig.model_validate(integration.config), claude.ClaudeCredentials.model_validate(secrets))
    integration.health, integration.last_checked_at = ("healthy" if result.ok else "error"), utcnow()
    integration.last_error, integration.last_error_class = (None, None) if result.ok else (result.detail[:1000], result.error_class)
    return {"ok": result.ok, "detail": result.detail, "status": _claude_status(db, principal, integration)}


@router.delete("/claude", status_code=204)
def claude_disconnect(db: Db, principal: Principal = require("admin:org")) -> None:
    integration = _claude_integration(db)
    if integration is None:
        return
    settings = service.load_settings(db, principal.organization_id)
    if settings.integration_id == integration.id:
        settings.enabled, settings.integration_id = False, None
        service.save_settings(db, principal.organization_id, settings)
    db.delete(integration)
    audit_event(db, principal, "ai_analytics.claude_disconnected", entity_type="integration", entity_id=integration.id)


@router.post("/briefing")
def executive_briefing(db: Db, principal: Principal = require("ai_analytics:use", "findings:read", "assets:read")) -> dict:
    """Plain-language summary of the organization's current exposure, built from live dashboard figures."""
    from app.domains.dashboard.router import overview

    data = overview(db, principal, trend_days=30)
    paths = db.execute(select(AttackPath).where(AttackPath.status == "active").order_by(AttackPath.score.desc()).limit(5)).scalars()
    facts = {
        "assets": data["assets"], "findings": {k: v for k, v in data["findings"].items() if k != "by_status"},
        "attack_paths": {**data["attack_paths"], "top": [{"title": p.title, "classification": p.classification, "severity": p.severity,
                                                          "business_impact": p.business_impact} for p in paths]},
        "cloud": data["cloud"], "ai": data["ai"], "remediation": data["remediation"], "compliance": data["compliance"],
        "top_findings": data["top_findings"],
        "trend": {"start": data["trend"][0] if data["trend"] else None, "end": data["trend"][-1] if data["trend"] else None},
    }
    result = service.analyse(db, principal, purpose="Write an executive briefing on current exposure and the three priorities for this week",
                             entity_type="organization", entity_id=principal.organization_id, facts=facts)
    audit_event(db, principal, "ai_analytics.used", entity_type="organization", entity_id=principal.organization_id,
                data={"feature": "briefing", "model": result["model"]})
    return result
