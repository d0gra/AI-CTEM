"""AI security posture management API: AI inventory, governance attributes and AI red team."""

import secrets
import uuid
from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select

from app.api.deps import Db, Paging, Principal, audit_event, like_escape, paginate, require
from app.core.errors import NotFound, ValidationFailed
from app.db.base import utcnow
from app.domains.assessments import service as assessments
from app.domains.assets import scope as scope_service
from app.domains.assets.service import AssetSpec, upsert_asset
from app.domains.policy.views import HIGH_IMPACT_CAPABILITIES, agent_tool_stats
from app.domains.risk.policy import load_policy, save_policy
from app.engines.ai.signatures import SIGNATURES
from app.engines.ai_redteam.catalog import PROFILES, RELATED_ENGINES, TESTS
from app.engines.ai_redteam.runner import RedTeamConfig
from app.integrations.llm.client import LlmConfig
from app.models import (
    AIAgent, AIAssessment, AIAssessmentTest, AIAsset, AIIntegration, AIModel, Assessment, AssessmentRun, Asset, Evidence,
    Finding, Integration, MCPServer,
)
from app.models.ai import APPROVAL_STATES, AUTONOMY_LEVELS
from app.models.asset import AI_ASSET_TYPES
from app.models.finding import AI_DOMAINS, OPEN_STATUSES

router = APIRouter(tags=["AI Security"])


class ToolIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=2000)
    capabilities: list[str] = Field(default=[], max_length=15)
    requires_approval: bool = False


class AIAssetIn(BaseModel):
    type: Literal[AI_ASSET_TYPES]  # type: ignore[valid-type]
    identifier: str = Field(min_length=1, max_length=1024)
    name: str = Field(min_length=1, max_length=512)
    environment: Literal["production", "staging", "development", "test", "unknown"] = "unknown"
    exposure: Literal["internet", "internal", "private", "unknown"] = "unknown"
    provider: str | None = Field(default=None, max_length=48)


class AIPosturePatch(BaseModel):
    """Governance and configuration attributes recorded by the owning team."""

    provider: str | None = Field(default=None, max_length=48)
    approval_status: Literal[APPROVAL_STATES] | None = None  # type: ignore[valid-type]
    managed: bool | None = None
    auth_required: bool | None = None
    rate_limited: bool | None = None
    processes_sensitive_data: bool | None = None
    tenant_isolation: Literal["enforced", "not_enforced", "not_applicable"] | None = None
    # agent
    autonomy_level: Literal[AUTONOMY_LEVELS] | None = None  # type: ignore[valid-type]
    human_approval_required: bool | None = None
    persistent_memory: bool | None = None
    can_delegate: bool | None = None
    processes_untrusted_input: bool | None = None
    identity_asset_id: uuid.UUID | None = None
    tools: list[ToolIn] | None = Field(default=None, max_length=200)
    # rag / vector store
    document_level_authorization: bool | None = None
    ingests_untrusted_content: bool | None = None
    ingestion_provenance_tracked: bool | None = None
    contains_sensitive_data: bool | None = None
    # model
    provenance_verified: bool | None = None
    provenance_detail: str | None = Field(default=None, max_length=2000)


class ApprovedProvidersIn(BaseModel):
    providers: list[str] = Field(max_length=100)


class RedTeamIn(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    integration_id: uuid.UUID
    profiles: list[str] = Field(default=["llm_application"], min_length=1)
    authorization_statement: str = Field(min_length=30, max_length=4000,
                                         description="Who authorized testing of this target, under what agreement, and any constraints")
    authorization_days: int = Field(default=14, ge=1, le=30)
    request_budget: int = Field(default=60, ge=1, le=500)
    rate_limit_per_minute: int = Field(default=20, ge=1, le=120)
    attempts: int = Field(default=2, ge=1, le=5)
    forbidden_markers: list[str] = Field(default=[], max_length=10)


AI_FIELDS = ("provider", "approval_status", "managed", "auth_required", "rate_limited", "processes_sensitive_data", "tenant_isolation")
AGENT_FIELDS = ("autonomy_level", "human_approval_required", "persistent_memory", "can_delegate", "processes_untrusted_input", "identity_asset_id")
ATTRIBUTE_FIELDS = ("document_level_authorization", "ingests_untrusted_content", "ingestion_provenance_tracked", "contains_sensitive_data")


def _get_ai_asset(db: Db, asset_id: uuid.UUID) -> Asset:
    asset = db.get(Asset, asset_id)
    if asset is None or asset.type not in AI_ASSET_TYPES:
        raise NotFound("AI asset not found")
    return asset


def _detail(db: Db, asset: Asset) -> dict:
    ai, agent, mcp, model = db.get(AIAsset, asset.id), db.get(AIAgent, asset.id), db.get(MCPServer, asset.id), db.get(AIModel, asset.id)
    open_findings = db.execute(select(func.count()).select_from(Finding).where(Finding.asset_id == asset.id, Finding.status.in_(OPEN_STATUSES))).scalar_one()
    out = {"id": asset.id, "type": asset.type, "name": asset.name, "identifier": asset.identifier, "environment": asset.environment,
           "exposure": asset.exposure, "criticality": asset.criticality, "data_sensitivity": asset.data_sensitivity,
           "owner_user_id": asset.owner_user_id, "owner_team_id": asset.owner_team_id, "risk_score": asset.risk_score,
           "discovery_sources": asset.discovery_sources, "last_seen_at": asset.last_seen_at, "open_findings": open_findings,
           "attributes": {k: (asset.attributes or {}).get(k) for k in ATTRIBUTE_FIELDS if k in (asset.attributes or {})},
           "ai": {f: getattr(ai, f) for f in AI_FIELDS} if ai else None, "agent": None, "mcp": None, "model": None}
    if agent:
        high, unapproved = agent_tool_stats(agent.tools or [])
        out["agent"] = {**{f: getattr(agent, f) for f in AGENT_FIELDS}, "tools": agent.tools, "high_impact_tools": high,
                        "unapproved_high_impact_tools": unapproved}
    if mcp:
        out["mcp"] = {"transport": mcp.transport, "endpoint": mcp.endpoint, "command": mcp.command, "auth_type": mcp.auth_type,
                      "uses_tls": mcp.uses_tls, "config_source": mcp.config_source, "server_info": mcp.server_info, "tools": mcp.tools,
                      "last_probed_at": mcp.last_probed_at}
    if model:
        out["model"] = {"model_name": model.model_name, "artifact_format": model.artifact_format, "sha256": model.sha256,
                        "size_bytes": model.size_bytes, "source_uri": model.source_uri, "provenance_verified": model.provenance_verified,
                        "provenance_detail": model.provenance_detail, "last_scanned_at": model.last_scanned_at}
    return out


@router.get("/ai/assets")
def list_ai_assets(db: Db, paging: Paging, _: Principal = require("ai:read"), q: str | None = Query(None, max_length=200),
                   type: list[str] | None = Query(None), approval_status: str | None = None, provider: str | None = None,
                   exposure: str | None = None, unowned: bool = False) -> dict:
    stmt = (select(Asset, AIAsset).outerjoin(AIAsset, AIAsset.asset_id == Asset.id)
            .where(Asset.type.in_(AI_ASSET_TYPES), Asset.status != "retired").order_by(Asset.risk_score.desc(), Asset.name))
    if q:
        pattern = f"%{like_escape(q)}%"
        stmt = stmt.where(or_(Asset.name.ilike(pattern), Asset.identifier.ilike(pattern), AIAsset.provider.ilike(pattern)))
    if type:
        stmt = stmt.where(Asset.type.in_(type))
    if approval_status:
        stmt = stmt.where(AIAsset.approval_status == approval_status)
    if provider:
        stmt = stmt.where(AIAsset.provider == provider)
    if exposure:
        stmt = stmt.where(Asset.exposure == exposure)
    if unowned:
        stmt = stmt.where(Asset.owner_user_id.is_(None), Asset.owner_team_id.is_(None))
    rows, total = paginate(db, stmt, paging, scalars=False)
    ids = [a.id for a, _ in rows]
    counts = dict(db.execute(select(Finding.asset_id, func.count()).where(Finding.asset_id.in_(ids), Finding.status.in_(OPEN_STATUSES))
                             .group_by(Finding.asset_id)).all()) if ids else {}
    return {"total": total, "page": paging.page, "page_size": paging.page_size, "items": [
        {"id": a.id, "type": a.type, "name": a.name, "identifier": a.identifier, "environment": a.environment, "exposure": a.exposure,
         "risk_score": a.risk_score, "has_owner": bool(a.owner_user_id or a.owner_team_id), "provider": x.provider if x else None,
         "approval_status": x.approval_status if x else "unknown", "managed": x.managed if x else False,
         "auth_required": x.auth_required if x else None, "open_findings": counts.get(a.id, 0), "last_seen_at": a.last_seen_at,
         "discovery_sources": a.discovery_sources} for a, x in rows]}


@router.post("/ai/assets", status_code=201)
def register_ai_asset(body: AIAssetIn, db: Db, principal: Principal = require("ai:write")) -> dict:
    asset, created = upsert_asset(db, AssetSpec(type=body.type, identifier=body.identifier, name=body.name, environment=body.environment,
                                                exposure=body.exposure, ai={"provider": body.provider, "managed": True}),
                                  source="manual", actor_user_id=principal.user_id)
    if body.type == "ai_agent" and db.get(AIAgent, asset.id) is None:
        db.add(AIAgent(organization_id=asset.organization_id, asset_id=asset.id))
    if body.type == "ai_model" and db.get(AIModel, asset.id) is None:
        db.add(AIModel(organization_id=asset.organization_id, asset_id=asset.id, model_name=body.name))
    db.flush()
    audit_event(db, principal, "ai.asset_registered", entity_type="asset", entity_id=asset.id, data={"type": body.type, "created": created})
    return _detail(db, asset)


@router.get("/ai/assets/{asset_id}")
def get_ai_asset(asset_id: uuid.UUID, db: Db, _: Principal = require("ai:read")) -> dict:
    return _detail(db, _get_ai_asset(db, asset_id))


@router.patch("/ai/assets/{asset_id}")
def update_ai_posture(asset_id: uuid.UUID, body: AIPosturePatch, db: Db, principal: Principal = require("ai:write")) -> dict:
    asset = _get_ai_asset(db, asset_id)
    changes = body.model_dump(exclude_unset=True)
    ai = db.get(AIAsset, asset.id)
    if ai is None:
        ai = AIAsset(organization_id=asset.organization_id, asset_id=asset.id)
        db.add(ai)
    dangerous_change = False
    for f in AI_FIELDS:
        if f in changes:
            if f in ("auth_required", "rate_limited") and changes[f] is False and getattr(ai, f) is not False:
                dangerous_change = True
            setattr(ai, f, changes[f])
    if any(f in changes for f in (*AGENT_FIELDS, "tools")):
        if asset.type != "ai_agent":
            raise ValidationFailed("Agent attributes can only be set on AI agents")
        agent = db.get(AIAgent, asset.id)
        if agent is None:
            agent = AIAgent(organization_id=asset.organization_id, asset_id=asset.id)
            db.add(agent)
        before = agent_tool_stats(agent.tools or [])[1]
        for f in AGENT_FIELDS:
            if f in changes:
                if f == "identity_asset_id" and changes[f] and db.get(Asset, changes[f]) is None:
                    raise ValidationFailed("Identity asset does not exist")
                if f == "human_approval_required" and changes[f] is False and agent.human_approval_required:
                    dangerous_change = True
                setattr(agent, f, changes[f])
        if "tools" in changes and body.tools is not None:
            unknown = {c for t in body.tools for c in t.capabilities} - (HIGH_IMPACT_CAPABILITIES | {"read", "search", "filesystem_read", "database_read"})
            if unknown:
                raise ValidationFailed(f"Unknown tool capabilities: {sorted(unknown)}")
            agent.tools = [t.model_dump() for t in body.tools]
            if agent_tool_stats(agent.tools)[1] > before:
                dangerous_change = True
    attrs = {f: changes[f] for f in ATTRIBUTE_FIELDS if f in changes}
    if attrs:
        asset.attributes = {**(asset.attributes or {}), **attrs}
    if "provenance_verified" in changes or "provenance_detail" in changes:
        if asset.type != "ai_model":
            raise ValidationFailed("Provenance can only be recorded for models")
        model = db.get(AIModel, asset.id)
        if model is None:
            model = AIModel(organization_id=asset.organization_id, asset_id=asset.id, model_name=asset.name)
            db.add(model)
        if changes.get("provenance_verified") and not (changes.get("provenance_detail") or model.provenance_detail):
            raise ValidationFailed("Describe how provenance was verified (source, digest or attestation)")
        for f in ("provenance_verified", "provenance_detail"):
            if f in changes and changes[f] is not None:
                setattr(model, f, changes[f])
    db.flush()
    audit_event(db, principal, "ai.posture_updated", entity_type="asset", entity_id=asset.id, data={"fields": sorted(changes)})
    if dangerous_change:
        from app.domains.notifications.service import notify

        notify(db, organization_id=asset.organization_id, event_type="ai.config_changed", severity="high",
               title=f"AI configuration weakened: {asset.name}", body=f"Changed by {principal.email}: {', '.join(sorted(changes))}",
               entity_type="asset", entity_id=asset.id)
    return _detail(db, asset)


@router.get("/ai/integrations")
def list_ai_integrations(db: Db, paging: Paging, _: Principal = require("ai:read"), provider: str | None = None) -> dict:
    stmt = (select(AIIntegration, Asset.name).join(Asset, Asset.id == AIIntegration.source_asset_id)
            .order_by(AIIntegration.provider, AIIntegration.location))
    if provider:
        stmt = stmt.where(AIIntegration.provider == provider)
    rows, total = paginate(db, stmt, paging, scalars=False)
    return {"total": total, "page": paging.page, "page_size": paging.page_size, "items": [
        {"id": i.id, "provider": i.provider, "category": i.category, "package": i.package, "version": i.version,
         "detection_method": i.detection_method, "location": i.location, "source_asset_id": i.source_asset_id, "source_name": name,
         "ai_asset_id": i.ai_asset_id, "first_seen_at": i.first_seen_at, "last_seen_at": i.last_seen_at} for i, name in rows]}


@router.get("/ai/governance")
def get_governance(db: Db, principal: Principal = require("ai:read")) -> dict:
    policy = load_policy(db, principal.organization_id)
    detected = dict(db.execute(select(AIAsset.provider, func.count()).join(Asset, Asset.id == AIAsset.asset_id)
                               .where(AIAsset.provider.isnot(None), Asset.type.in_(("ai_provider", "llm_endpoint", "ai_application")))
                               .group_by(AIAsset.provider)).all())
    return {"approved_ai_providers": policy.approved_ai_providers, "detected_providers": detected,
            "known_providers": [{"key": s.key, "name": s.name, "category": s.category} for s in SIGNATURES if s.category in ("provider", "serving")],
            "visibility_note": "Shadow-AI detection covers only the configured sources: analysed repositories, probed endpoints, "
                               "cloud inventory and manually registered assets. Employee use of AI tools outside these sources is not observed."}


@router.put("/ai/governance/approved-providers")
def set_approved_providers(body: ApprovedProvidersIn, db: Db, principal: Principal = require("ai:write", "risk:configure")) -> dict:
    known = {s.key for s in SIGNATURES}
    unknown = {p for p in body.providers if p not in known}
    if unknown:
        raise ValidationFailed(f"Unknown providers: {sorted(unknown)}", details={"known": sorted(known)})
    policy = load_policy(db, principal.organization_id)
    policy.approved_ai_providers = sorted(set(body.providers))
    save_policy(db, principal.organization_id, policy)
    # Apply the decision to already-discovered provider assets.
    for ai, _asset in db.execute(select(AIAsset, Asset).join(Asset, Asset.id == AIAsset.asset_id).where(Asset.type == "ai_provider")).all():
        if ai.provider:
            ai.approval_status = ("approved" if ai.provider in policy.approved_ai_providers else "unapproved") if policy.approved_ai_providers else "unknown"
    audit_event(db, principal, "ai.approved_providers_updated", data={"providers": policy.approved_ai_providers})
    return {"approved_ai_providers": policy.approved_ai_providers}


# --- AI red team -------------------------------------------------------------------------

@router.get("/ai-redteam/catalog")
def redteam_catalog(_: Principal = require("ai:read")) -> dict:
    return {"profiles": PROFILES, "related_engines": RELATED_ENGINES, "tests": [
        {"id": t.id, "profile": t.profile, "title": t.title, "threat_category": t.threat_category, "owasp_llm": t.owasp_llm,
         "atlas_technique": t.atlas, "nist_ai_rmf": t.nist, "objective": t.objective, "preconditions": t.preconditions,
         "procedure": t.procedure, "severity": t.severity, "remediation": t.remediation, "needs_tools": t.needs_tools} for t in TESTS],
        "safety": ["Written authorization with an expiry is required before any request is sent.",
                   "The target endpoint must be in authorized scope with active testing allowed.",
                   "Requests are capped by a per-run budget and a per-minute rate limit.",
                   "Tools requested by the target are recorded and never executed.",
                   "Payloads are benign marker-echo tests; leak tests use synthetic canary data.",
                   "Runs support dry-run and cancellation; every exchange is stored as evidence."]}


def _rt_out(db: Db, a: Assessment, envelope: AIAssessment) -> dict:
    target = db.get(Asset, envelope.target_asset_id)
    last = db.execute(select(AssessmentRun).where(AssessmentRun.assessment_id == a.id).order_by(AssessmentRun.created_at.desc()).limit(1)).scalar_one_or_none()
    return {"id": a.id, "name": a.name, "profiles": envelope.profiles, "target_asset_id": envelope.target_asset_id,
            "target_name": target.name if target else None, "integration_id": envelope.integration_id,
            "authorization_statement": envelope.authorization_statement, "authorized_by_user_id": envelope.authorized_by_user_id,
            "authorized_at": envelope.authorized_at, "authorization_expires_at": envelope.authorization_expires_at,
            "authorization_current": envelope.authorization_expires_at > utcnow(), "request_budget": envelope.request_budget,
            "rate_limit_per_minute": envelope.rate_limit_per_minute, "config": a.config, "created_at": a.created_at,
            "last_run": {"id": last.id, "status": last.status, "dry_run": last.dry_run, "created_at": last.created_at,
                         "summary": last.summary, "error": last.error, "job_id": last.job_id} if last else None}


@router.get("/ai-redteam/assessments")
def list_redteam(db: Db, _: Principal = require("ai:read", "assessments:read")) -> list[dict]:
    rows = db.execute(select(Assessment, AIAssessment).join(AIAssessment, AIAssessment.assessment_id == Assessment.id)
                      .order_by(Assessment.created_at.desc())).all()
    return [_rt_out(db, a, e) for a, e in rows]


@router.post("/ai-redteam/assessments", status_code=201)
def create_redteam(body: RedTeamIn, db: Db, principal: Principal = require("ai_redteam:run")) -> dict:
    unknown = set(body.profiles) - set(PROFILES)
    if unknown:
        raise ValidationFailed(f"Unknown profiles: {sorted(unknown)}", details={"profiles": sorted(PROFILES)})
    integration = db.get(Integration, body.integration_id)
    if integration is None or integration.connector != "llm" or not integration.enabled:
        raise ValidationFailed("Select an enabled LLM endpoint integration as the target")
    llm = LlmConfig.model_validate(integration.config)
    scope_service.check_scope(db, llm.endpoint, active=True)  # refuse targets that are not explicitly authorized
    harness = llm.api_style != "custom_http"
    asset, _created = upsert_asset(db, AssetSpec(
        type="llm_endpoint" if harness else "ai_application", identifier=f"{llm.endpoint}#{llm.model or 'application'}",
        name=integration.name, attributes={"api_style": llm.api_style, "model": llm.model},
        ai={"provider": "anthropic" if llm.api_style == "anthropic" else None, "managed": True}), source="ai_redteam", actor_user_id=principal.user_id)
    config = RedTeamConfig(profiles=body.profiles, attempts=body.attempts, forbidden_markers=body.forbidden_markers)
    a = Assessment(organization_id=principal.organization_id, name=body.name, kind="ai_redteam", config=config.model_dump(),
                   integration_id=integration.id, created_by_user_id=principal.user_id)
    db.add(a)
    db.flush()
    now = utcnow()
    envelope = AIAssessment(
        organization_id=principal.organization_id, assessment_id=a.id, target_asset_id=asset.id, integration_id=integration.id,
        profiles=body.profiles, authorization_statement=body.authorization_statement, authorized_by_user_id=principal.user_id,
        authorized_at=now, authorization_expires_at=now + timedelta(days=body.authorization_days), request_budget=body.request_budget,
        rate_limit_per_minute=body.rate_limit_per_minute, canary_token=f"CANARY-{secrets.token_hex(8).upper()}")
    db.add(envelope)
    db.flush()
    audit_event(db, principal, "ai_redteam.authorized", entity_type="assessment", entity_id=a.id, data={
        "target": llm.endpoint, "model": llm.model, "profiles": body.profiles, "statement": body.authorization_statement,
        "expires_at": envelope.authorization_expires_at.isoformat(), "request_budget": body.request_budget})
    return _rt_out(db, a, envelope)


@router.get("/ai-redteam/assessments/{assessment_id}")
def get_redteam(assessment_id: uuid.UUID, db: Db, _: Principal = require("ai:read", "assessments:read")) -> dict:
    a, envelope = db.get(Assessment, assessment_id), db.get(AIAssessment, assessment_id)
    if a is None or envelope is None:
        raise NotFound("AI red team assessment not found")
    runs = db.execute(select(AssessmentRun).where(AssessmentRun.assessment_id == a.id).order_by(AssessmentRun.created_at.desc()).limit(20)).scalars()
    return {**_rt_out(db, a, envelope), "runs": [{"id": r.id, "status": r.status, "dry_run": r.dry_run, "created_at": r.created_at,
                                                  "finished_at": r.finished_at, "summary": r.summary, "error": r.error} for r in runs]}


@router.post("/ai-redteam/assessments/{assessment_id}/run", status_code=202)
def run_redteam(assessment_id: uuid.UUID, db: Db, principal: Principal = require("ai_redteam:run"), dry_run: bool = False) -> dict:
    from app.engines.ai_redteam.runner import assert_authorization_current

    a = db.get(Assessment, assessment_id)
    if a is None or a.kind != "ai_redteam":
        raise NotFound("AI red team assessment not found")
    assert_authorization_current(db, a)
    run = assessments.start_run(db, a, principal, dry_run=dry_run)
    return {"run_id": run.id, "job_id": run.job_id, "status": run.status, "dry_run": run.dry_run}


@router.get("/ai-redteam/runs/{run_id}/tests")
def run_tests(run_id: uuid.UUID, db: Db, _: Principal = require("ai:read", "findings:read")) -> list[dict]:
    if db.get(AssessmentRun, run_id) is None:
        raise NotFound("Run not found")
    rows = db.execute(select(AIAssessmentTest, Evidence).outerjoin(Evidence, Evidence.id == AIAssessmentTest.evidence_id)
                      .where(AIAssessmentTest.assessment_run_id == run_id).order_by(AIAssessmentTest.test_id)).all()
    return [{"id": t.id, "test_id": t.test_id, "profile": t.profile, "threat_category": t.threat_category, "owasp_llm": t.owasp_llm,
             "atlas_technique": t.atlas_technique, "nist_ai_rmf": t.nist_ai_rmf, "objective": t.objective,
             "preconditions": t.preconditions, "scope": t.scope, "procedure": t.procedure, "execution_status": t.execution_status,
             "outcome": t.outcome, "observed_behavior": t.observed_behavior, "confidence": t.confidence, "severity": t.severity,
             "reproducibility": {"attempts": t.attempts, "reproduced": t.reproduced}, "remediation": t.remediation,
             "retest_result": t.retest_result, "finding_id": t.finding_id, "executed_at": t.executed_at,
             "evidence": ev.content if ev else None} for t, ev in rows]


@router.get("/ai/findings-summary")
def ai_findings_summary(db: Db, _: Principal = require("ai:read")) -> dict:
    rows = db.execute(select(Finding.domain, Finding.risk_level, func.count()).where(Finding.domain.in_(AI_DOMAINS), Finding.status.in_(OPEN_STATUSES))
                      .group_by(Finding.domain, Finding.risk_level)).all()
    out: dict = {}
    for domain, level, count in rows:
        out.setdefault(domain, {})[level] = count
    return out
