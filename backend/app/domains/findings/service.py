"""Finding normalisation, de-duplication, lifecycle and evidence. Every engine and scanner
adapter produces `FindingInput` objects and hands them to `ingest`."""

import hashlib
import re
import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import ValidationFailed
from app.db.base import utcnow
from app.db.session import org_of
from app.domains.notifications.service import notify
from app.domains.risk import service as risk
from app.models import AIFinding, Asset, Evidence, Finding, FindingEvent, Vulnerability
from app.models.finding import AI_DOMAINS, FINDING_DOMAINS, OPEN_STATUSES, SEVERITIES

# Allowed manual transitions. Automated transitions (reopen, verified by retest) are applied by
# the service and recorded on the timeline.
TRANSITIONS: dict[str, set[str]] = {
    "new": {"triaged", "assigned", "in_progress", "false_positive", "accepted_risk"},
    "triaged": {"assigned", "in_progress", "false_positive", "accepted_risk", "pending_validation"},
    "assigned": {"in_progress", "triaged", "pending_validation", "false_positive", "accepted_risk"},
    "in_progress": {"pending_validation", "assigned", "false_positive", "accepted_risk"},
    "pending_validation": {"remediated", "in_progress"},
    "remediated": {"closed", "in_progress"},
    "accepted_risk": {"triaged", "in_progress"},
    "false_positive": {"triaged"},
    "closed": {"triaged"},
}

_SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization:\s*(?:bearer|basic)\s+)[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)((?:api[_-]?key|token|secret|password|passwd)[\"']?\s*[:=]\s*[\"']?)[^\s\"',;&]{6,}"),
    re.compile(r"\b(sk-(?:ant-|proj-)?[A-Za-z0-9_-]{4})[A-Za-z0-9_-]{16,}"),
    re.compile(r"\b(AKIA[0-9A-Z]{4})[0-9A-Z]{12}\b"),
    re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{4})[A-Za-z0-9]{30,}"),
    re.compile(r"\b(hf_[A-Za-z0-9]{4})[A-Za-z0-9]{26,}"),
    re.compile(r"\b(AIza[0-9A-Za-z_-]{4})[0-9A-Za-z_-]{31}\b"),
    re.compile(r"\b(xox[baprs]-[A-Za-z0-9]{4})[A-Za-z0-9-]{10,}"),
    re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)[\s\S]+?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
]


def redact(value):
    """Mask credential material before evidence is stored."""
    if isinstance(value, str):
        for pattern in _SECRET_PATTERNS:
            value = pattern.sub(lambda m: m.group(1) + "[REDACTED]", value)
        return value
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


@dataclass
class EvidenceInput:
    kind: str
    summary: str
    content: dict = field(default_factory=dict)


@dataclass
class FindingInput:
    asset: Asset
    source: str
    rule_id: str
    domain: str
    title: str
    severity: str
    description: str = ""
    confidence: str = "firm"
    remediation: str = ""
    reproduction: str = ""
    technical_impact: str = ""
    business_impact: str = ""
    references: list[str] = field(default_factory=list)
    cwe: str | None = None
    attributes: dict = field(default_factory=dict)
    vulnerability_id: str | None = None  # external id (CVE-..., GHSA-...) resolved against the catalogue
    discriminator: str = ""  # distinguishes multiple instances of one rule on one asset
    evidence: list[EvidenceInput] = field(default_factory=list)
    owasp_llm: str | None = None
    atlas_technique: str | None = None
    nist_ai_rmf: str | None = None
    test_id: str | None = None


def dedup_key(asset_id: uuid.UUID, source: str, rule_id: str, discriminator: str) -> str:
    return hashlib.sha256(f"{asset_id}|{source}|{rule_id}|{discriminator}".encode()).hexdigest()


def add_event(db: Session, finding: Finding, event_type: str, data: dict | None = None,
              actor_user_id: uuid.UUID | None = None) -> None:
    db.add(FindingEvent(organization_id=finding.organization_id, finding_id=finding.id, event_type=event_type,
                        data=data or {}, actor_user_id=actor_user_id, occurred_at=utcnow()))


def add_evidence(db: Session, finding: Finding, item: EvidenceInput, run_id: uuid.UUID | None = None,
                 user_id: uuid.UUID | None = None) -> Evidence:
    row = Evidence(organization_id=finding.organization_id, finding_id=finding.id, assessment_run_id=run_id,
                   kind=item.kind, summary=redact(item.summary)[:1000], content=redact(item.content),
                   created_by_user_id=user_id, created_at=utcnow())
    db.add(row)
    return row


def resolve_vulnerability(db: Session, external_id: str | None) -> Vulnerability | None:
    if not external_id:
        return None
    external_id = external_id.strip().upper() if external_id.upper().startswith("CVE-") else external_id.strip()
    vuln = db.execute(select(Vulnerability).where(Vulnerability.external_id == external_id)).scalar_one_or_none()
    if vuln is None:
        # Create a catalogue stub; threat-intel synchronisation enriches it later.
        try:
            with db.begin_nested():
                vuln = Vulnerability(external_id=external_id, source="scanner")
                db.add(vuln)
                db.flush()
        except Exception:
            vuln = db.execute(select(Vulnerability).where(Vulnerability.external_id == external_id)).scalar_one()
    return vuln


def ingest(db: Session, item: FindingInput, *, run_id: uuid.UUID | None = None) -> tuple[Finding, bool]:
    """Create or refresh a finding. Returns (finding, created)."""
    if item.severity not in SEVERITIES:
        raise ValueError(f"Unknown severity {item.severity!r}")
    if item.domain not in FINDING_DOMAINS:
        raise ValueError(f"Unknown finding domain {item.domain!r}")
    org_id = org_of(db)
    now = utcnow()
    key = dedup_key(item.asset.id, item.source, item.rule_id, item.discriminator)
    vuln = resolve_vulnerability(db, item.vulnerability_id)
    finding = db.execute(select(Finding).where(Finding.dedup_key == key)).scalar_one_or_none()
    created = finding is None
    if finding is None:
        finding = Finding(
            organization_id=org_id, asset_id=item.asset.id, vulnerability_id=vuln.id if vuln else None,
            assessment_run_id=run_id, dedup_key=key, source=item.source, rule_id=item.rule_id[:200],
            domain=item.domain, title=redact(item.title)[:512], description=redact(item.description),
            severity=item.severity, confidence=item.confidence, technical_impact=item.technical_impact,
            business_impact=item.business_impact, remediation=item.remediation, reproduction=redact(item.reproduction),
            references=item.references[:30], cwe=item.cwe, attributes=redact(item.attributes),
            first_seen_at=now, last_seen_at=now,
        )
        db.add(finding)
        db.flush()
        add_event(db, finding, "created", {"source": item.source, "run_id": str(run_id) if run_id else None})
        if item.domain in AI_DOMAINS or item.owasp_llm or item.atlas_technique:
            db.add(AIFinding(organization_id=org_id, finding_id=finding.id, owasp_llm=item.owasp_llm,
                             atlas_technique=item.atlas_technique, nist_ai_rmf=item.nist_ai_rmf,
                             test_id=item.test_id))
        for ev in item.evidence[:10]:
            add_evidence(db, finding, ev, run_id)
    else:
        finding.last_seen_at = now
        finding.assessment_run_id = run_id or finding.assessment_run_id
        if finding.severity != item.severity:
            add_event(db, finding, "severity_changed", {"from": finding.severity, "to": item.severity})
            finding.severity = item.severity
        if vuln and finding.vulnerability_id is None:
            finding.vulnerability_id = vuln.id
        if finding.status in ("remediated", "closed"):
            add_event(db, finding, "reopened", {"from": finding.status, "reason": "Observed again by " + item.source})
            finding.status, finding.resolved_at, finding.due_at = "new", None, None
            finding.first_seen_at = now  # SLA restarts for a regression
            for ev in item.evidence[:10]:
                add_evidence(db, finding, ev, run_id)
        elif finding.status == "pending_validation":
            add_event(db, finding, "retest", {"result": "still_present", "run_id": str(run_id) if run_id else None})
            finding.status = "in_progress"
            sync_tasks(db, finding)
            for ev in item.evidence[:3]:
                add_evidence(db, finding, ev, run_id)
    db.flush()
    result = risk.score_finding(db, finding, item.asset)
    if created and finding.status in OPEN_STATUSES:
        if result.level == "critical":
            notify(db, organization_id=org_id, event_type="finding.critical", severity="critical",
                   title=f"Critical finding: {finding.title}", body=f"Asset: {item.asset.name}",
                   entity_type="finding", entity_id=finding.id)
        elif vuln is not None and vuln.kev:
            notify(db, organization_id=org_id, event_type="finding.exploited", severity="high",
                   title=f"Known-exploited vulnerability: {finding.title}", body=f"Asset: {item.asset.name}",
                   entity_type="finding", entity_id=finding.id)
        if item.domain in AI_DOMAINS and result.level in ("critical", "high"):
            notify(db, organization_id=org_id, event_type="ai.risk", severity=result.level,
                   title=f"AI risk: {finding.title}", body=f"Asset: {item.asset.name}", entity_type="finding",
                   entity_id=finding.id)
    return finding, created


def reconcile_unobserved(db: Session, *, source: str, asset_ids: set[uuid.UUID], observed: set[uuid.UUID],
                         run_id: uuid.UUID | None, rule_prefix: str | None = None) -> dict:
    """After a complete run of `source` over `asset_ids`, handle findings that were not seen.

    A finding awaiting validation that is no longer observed is marked remediated (the retest
    verified the fix). Other open findings are only annotated: absence from one scan is not
    treated as proof of remediation.
    """
    if not asset_ids:
        return {"verified_remediated": 0, "not_observed": 0}
    stmt = select(Finding).where(Finding.source == source, Finding.asset_id.in_(asset_ids),
                                 Finding.status.in_(OPEN_STATUSES))
    if rule_prefix:
        stmt = stmt.where(Finding.rule_id.startswith(rule_prefix))
    verified = unobserved = 0
    now = utcnow()
    for finding in db.execute(stmt).scalars():
        if finding.id in observed:
            continue
        if finding.status == "pending_validation":
            finding.status, finding.resolved_at = "remediated", now
            add_event(db, finding, "retest", {"result": "not_present", "run_id": str(run_id) if run_id else None})
            add_event(db, finding, "status_changed", {"from": "pending_validation", "to": "remediated",
                                                      "reason": "Verified by retest"})
            sync_tasks(db, finding)
            verified += 1
        else:
            finding.attributes = {**(finding.attributes or {}), "last_not_observed_at": now.isoformat()}
            unobserved += 1
    db.flush()
    risk.refresh_asset_risk(db, asset_ids)
    return {"verified_remediated": verified, "not_observed": unobserved}


def transition(db: Session, finding: Finding, new_status: str, *, actor_user_id: uuid.UUID, note: str = "",
               force: bool = False) -> None:
    if new_status == finding.status:
        return
    if not force and new_status not in TRANSITIONS.get(finding.status, set()):
        raise ValidationFailed(f"Cannot move a finding from {finding.status} to {new_status}",
                               details={"allowed": sorted(TRANSITIONS.get(finding.status, set()))})
    previous = finding.status
    finding.status = new_status
    finding.resolved_at = utcnow() if new_status not in OPEN_STATUSES else None
    add_event(db, finding, "status_changed", {"from": previous, "to": new_status, "note": note}, actor_user_id)
    sync_tasks(db, finding, actor_user_id)
    db.flush()
    risk.refresh_asset_risk(db, {finding.asset_id})


def sync_tasks(db: Session, finding: Finding, actor_user_id: uuid.UUID | None = None) -> None:
    """Keep remediation tasks consistent with the finding's verified state."""
    from app.models import RemediationTask

    tasks = db.execute(select(RemediationTask).where(RemediationTask.finding_id == finding.id,
                                                     RemediationTask.status.notin_(("done", "cancelled")))).scalars()
    now = utcnow()
    for task in tasks:
        if finding.status in ("remediated", "closed"):
            task.status, task.verified_at, task.verified_by_user_id = "done", now, actor_user_id
            task.completed_at = task.completed_at or now
        elif finding.status in ("false_positive", "accepted_risk"):
            task.status = "cancelled"
        elif finding.status == "in_progress" and task.status == "pending_validation":
            task.status, task.completed_at = "in_progress", None  # retest showed the fix did not hold
