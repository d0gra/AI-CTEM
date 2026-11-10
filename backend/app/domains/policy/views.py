"""Entity views: the flat documents that policy rules are evaluated against."""

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models import AIAgent, AIAsset, AIModel, Asset, Finding, MCPServer
from app.models.finding import OPEN_STATUSES

HIGH_IMPACT_CAPABILITIES = {
    "code_execution", "shell", "filesystem_write", "payment", "email_send", "database_write", "deploy",
    "iam_admin", "delete", "external_http", "browser",
}

ASSET_FIELDS = [
    "type", "identifier", "name", "environment", "criticality", "exposure", "data_sensitivity", "business_unit",
    "tags", "status", "has_owner", "risk_score", "attributes.*", "ai.provider", "ai.approval_status",
    "ai.managed", "ai.auth_required", "ai.rate_limited", "ai.processes_sensitive_data", "ai.tenant_isolation",
    "agent.autonomy_level", "agent.human_approval_required", "agent.persistent_memory",
    "agent.high_impact_tools", "agent.unapproved_high_impact_tools", "mcp.transport", "mcp.auth_type",
    "mcp.uses_tls", "model.artifact_format", "model.provenance_verified",
]
FINDING_FIELDS = [
    "domain", "severity", "status", "risk_level", "risk_score", "confidence", "source", "has_owner",
    "age_days", "sla_breached", "asset.type", "asset.environment", "asset.exposure", "asset.criticality",
]


def tool_is_high_impact(tool: dict) -> bool:
    return bool(HIGH_IMPACT_CAPABILITIES & set(tool.get("capabilities") or []))


def agent_tool_stats(tools: list) -> tuple[int, int]:
    high = [t for t in tools if isinstance(t, dict) and tool_is_high_impact(t)]
    return len(high), sum(1 for t in high if not t.get("requires_approval"))


def asset_views(db: Session) -> list[tuple[Asset, dict]]:
    assets = list(db.execute(select(Asset).where(Asset.status != "retired")).scalars())
    ai = {a.asset_id: a for a in db.execute(select(AIAsset)).scalars()}
    agents = {a.asset_id: a for a in db.execute(select(AIAgent)).scalars()}
    mcps = {m.asset_id: m for m in db.execute(select(MCPServer)).scalars()}
    models = {m.asset_id: m for m in db.execute(select(AIModel)).scalars()}
    out = []
    for a in assets:
        view: dict = {
            "type": a.type, "identifier": a.identifier, "name": a.name, "environment": a.environment,
            "criticality": a.criticality, "exposure": a.exposure, "data_sensitivity": a.data_sensitivity,
            "business_unit": a.business_unit, "tags": a.tags, "status": a.status,
            "has_owner": bool(a.owner_user_id or a.owner_team_id), "risk_score": a.risk_score,
            "attributes": a.attributes or {},
        }
        if (x := ai.get(a.id)) is not None:
            view["ai"] = {
                "provider": x.provider, "approval_status": x.approval_status, "managed": x.managed,
                "auth_required": x.auth_required, "rate_limited": x.rate_limited,
                "processes_sensitive_data": x.processes_sensitive_data, "tenant_isolation": x.tenant_isolation,
            }
        if (g := agents.get(a.id)) is not None:
            high, unapproved = agent_tool_stats(g.tools or [])
            view["agent"] = {
                "autonomy_level": g.autonomy_level, "human_approval_required": g.human_approval_required,
                "persistent_memory": g.persistent_memory, "high_impact_tools": high,
                "unapproved_high_impact_tools": unapproved,
            }
        if (m := mcps.get(a.id)) is not None:
            view["mcp"] = {"transport": m.transport, "auth_type": m.auth_type, "uses_tls": m.uses_tls}
        if (md := models.get(a.id)) is not None:
            view["model"] = {"artifact_format": md.artifact_format, "provenance_verified": md.provenance_verified}
        out.append((a, view))
    return out


def finding_view(f: Finding, asset: Asset | None, now: datetime) -> dict:
    return {
        "domain": f.domain, "severity": f.severity, "status": f.status, "risk_level": f.risk_level,
        "risk_score": f.risk_score, "confidence": f.confidence, "source": f.source,
        "has_owner": bool(f.owner_user_id or f.owner_team_id),
        "age_days": (now - f.first_seen_at).days,
        "sla_breached": bool(f.due_at and f.due_at < now and f.status in OPEN_STATUSES),
        "asset": {
            "type": asset.type, "environment": asset.environment, "exposure": asset.exposure,
            "criticality": asset.criticality,
        } if asset else {},
    }


def finding_views(db: Session) -> list[tuple[Finding, dict]]:
    now = utcnow()
    rows = db.execute(
        select(Finding, Asset).join(Asset, Asset.id == Finding.asset_id).where(Finding.status.in_(OPEN_STATUSES))
    ).all()
    return [(f, finding_view(f, a, now)) for f, a in rows]
