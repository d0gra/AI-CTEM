"""Risk scoring against database state."""

import uuid
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.domains.policy.views import agent_tool_stats
from app.domains.risk import engine
from app.domains.risk.policy import RiskPolicy, load_policy
from app.models import (
    AIAgent,
    AIAsset,
    Asset,
    AttackPath,
    AttackPathEdge,
    Finding,
    RiskScore,
    Vulnerability,
)
from app.models.finding import OPEN_STATUSES

_PATH_RANK = {"verified": 3, "probable": 2, "theoretical": 1}


def _strongest_path(db: Session, finding_id: uuid.UUID) -> str | None:
    rows = db.execute(
        select(AttackPath.classification)
        .join(AttackPathEdge, AttackPathEdge.attack_path_id == AttackPath.id)
        .where(AttackPathEdge.enabling_finding_id == finding_id, AttackPath.status == "active")
    ).scalars()
    return max(rows, key=lambda c: _PATH_RANK.get(c, 0), default=None)


def build_inputs(db: Session, finding: Finding, asset: Asset) -> engine.RiskInputs:
    vuln = db.get(Vulnerability, finding.vulnerability_id) if finding.vulnerability_id else None
    inputs = engine.RiskInputs(
        severity=finding.severity, confidence=finding.confidence, exposure=asset.exposure,
        asset_criticality=asset.criticality, data_sensitivity=asset.data_sensitivity,
        has_vulnerability_context=vuln is not None,
        attack_path_classification=_strongest_path(db, finding.id),
        privileged_identity=asset.type == "identity" and bool((asset.attributes or {}).get("privileged")),
    )
    if vuln is not None:
        inputs.cvss_score, inputs.epss_score = vuln.cvss_score, vuln.epss_score
        inputs.epss_percentile, inputs.kev = vuln.epss_percentile, vuln.kev
        inputs.exploit_available = vuln.exploit_available
    ai = db.get(AIAsset, asset.id)
    if ai is not None:
        inputs.ai_sensitive_data = bool(ai.processes_sensitive_data)
        inputs.ai_tenant_isolation_missing = ai.tenant_isolation == "not_enforced"
    agent = db.get(AIAgent, asset.id)
    if agent is not None:
        inputs.ai_autonomous = agent.autonomy_level == "autonomous" and not agent.human_approval_required
        inputs.ai_unapproved_high_impact_tools = agent_tool_stats(agent.tools or [])[1]
    return inputs


def score_finding(db: Session, finding: Finding, asset: Asset | None = None, policy: RiskPolicy | None = None,
                  *, record: bool = True) -> engine.RiskResult:
    asset = asset or db.get(Asset, finding.asset_id)
    assert asset is not None
    policy = policy or load_policy(db, finding.organization_id)
    result = engine.score(build_inputs(db, finding, asset), policy)
    changed = finding.risk_score != result.score or finding.risk_level != result.level
    finding.risk_score, finding.risk_level = result.score, result.level
    if finding.due_at is None and finding.status in OPEN_STATUSES and result.level in policy.sla_hours:
        finding.due_at = finding.first_seen_at + timedelta(hours=policy.sla_hours[result.level])
    if record and changed:
        db.add(RiskScore(organization_id=finding.organization_id, finding_id=finding.id, score=result.score,
                         level=result.level, breakdown=result.breakdown, policy_version=policy.version,
                         calculated_at=utcnow()))
    return result


def refresh_asset_risk(db: Session, asset_ids: set[uuid.UUID] | None = None) -> None:
    """Asset risk is the highest open finding score, plus a small bump for volume."""
    stmt = select(Asset)
    if asset_ids is not None:
        if not asset_ids:
            return
        stmt = stmt.where(Asset.id.in_(asset_ids))
    for asset in db.execute(stmt).scalars():
        scores = sorted(db.execute(
            select(Finding.risk_score).where(Finding.asset_id == asset.id, Finding.status.in_(OPEN_STATUSES))
        ).scalars(), reverse=True)
        asset.risk_score = round(min(100.0, scores[0] + min(5.0, 0.5 * (len(scores) - 1))), 1) if scores else 0.0


def recalculate_all(db: Session, organization_id: uuid.UUID) -> dict:
    policy = load_policy(db, organization_id)
    rows = db.execute(
        select(Finding, Asset).join(Asset, Asset.id == Finding.asset_id).where(Finding.status.in_(OPEN_STATUSES))
    ).all()
    changed = 0
    for finding, asset in rows:
        before = (finding.risk_score, finding.risk_level)
        score_finding(db, finding, asset, policy)
        changed += before != (finding.risk_score, finding.risk_level)
    db.flush()
    refresh_asset_risk(db)
    return {"findings": len(rows), "changed": changed, "policy_version": policy.version}
