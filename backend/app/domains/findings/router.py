import uuid
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, File, Form, Query, Response, UploadFile
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, or_, select

from app.api.deps import Db, Page, Paging, Principal, audit_event, like_escape, paginate, require
from app.core import storage
from app.core.config import get_settings
from app.core.errors import Conflict, NotFound, ValidationFailed
from app.core.security import sha256_hex
from app.db.base import utcnow
from app.domains.findings import service
from app.models import (
    AIFinding,
    Assessment,
    AssessmentRun,
    Asset,
    Evidence,
    Finding,
    FindingEvent,
    RemediationTask,
    RiskAcceptance,
    RiskScore,
    Team,
    User,
    Vulnerability,
)
from app.models.finding import AI_DOMAINS, FINDING_DOMAINS, FINDING_STATUSES, OPEN_STATUSES, SEVERITIES

router = APIRouter(tags=["Findings"])

SORTABLE = {"risk_score": Finding.risk_score, "severity": Finding.severity, "first_seen_at": Finding.first_seen_at,
            "last_seen_at": Finding.last_seen_at, "due_at": Finding.due_at, "title": Finding.title,
            "status": Finding.status}
# Evidence uploads: allow-listed by extension AND by leading bytes; stored as opaque blobs and
# always served as attachments.
UPLOAD_TYPES: dict[str, tuple[str, tuple[bytes, ...]]] = {
    ".png": ("image/png", (b"\x89PNG\r\n\x1a\n",)),
    ".jpg": ("image/jpeg", (b"\xff\xd8\xff",)),
    ".jpeg": ("image/jpeg", (b"\xff\xd8\xff",)),
    ".pdf": ("application/pdf", (b"%PDF-",)),
    ".txt": ("text/plain", ()),
    ".log": ("text/plain", ()),
    ".json": ("application/json", ()),
    ".csv": ("text/csv", ()),
    ".har": ("application/json", ()),
    ".xml": ("application/xml", ()),
}


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    asset_id: uuid.UUID
    asset_name: str = ""
    asset_type: str = ""
    title: str
    domain: str
    source: str
    rule_id: str
    severity: str
    confidence: str
    status: str
    risk_score: float
    risk_level: str
    owner_user_id: uuid.UUID | None
    owner_team_id: uuid.UUID | None
    due_at: datetime | None
    first_seen_at: datetime
    last_seen_at: datetime
    vulnerability_external_id: str | None = None
    kev: bool = False
    overdue: bool = False


class FindingPatch(BaseModel):
    status: Literal[FINDING_STATUSES] | None = None  # type: ignore[valid-type]
    note: str = Field(default="", max_length=4000)
    owner_user_id: uuid.UUID | None = None
    owner_team_id: uuid.UUID | None = None
    due_at: datetime | None = None


class ManualFindingIn(BaseModel):
    asset_id: uuid.UUID
    title: str = Field(min_length=3, max_length=512)
    description: str = Field(default="", max_length=20000)
    severity: Literal[SEVERITIES]  # type: ignore[valid-type]
    domain: Literal[FINDING_DOMAINS]  # type: ignore[valid-type]
    confidence: Literal["confirmed", "firm", "tentative"] = "firm"
    remediation: str = Field(default="", max_length=20000)
    reproduction: str = Field(default="", max_length=20000)
    technical_impact: str = Field(default="", max_length=5000)
    business_impact: str = Field(default="", max_length=5000)
    references: list[str] = Field(default=[], max_length=20)
    cve: str | None = Field(default=None, pattern=r"^CVE-\d{4}-\d{4,}$")


class CommentIn(BaseModel):
    body: str = Field(min_length=1, max_length=8000)


class VerifyIn(BaseModel):
    result: Literal["fixed", "still_present"]
    note: str = Field(min_length=5, max_length=4000)


def _get(db: Db, finding_id: uuid.UUID) -> Finding:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise NotFound("Finding not found")
    return finding


def _out(f: Finding, asset: Asset | None, vuln: Vulnerability | None) -> FindingOut:
    now = utcnow()
    return FindingOut.model_validate(f).model_copy(update={
        "asset_name": asset.name if asset else "", "asset_type": asset.type if asset else "",
        "vulnerability_external_id": vuln.external_id if vuln else None, "kev": bool(vuln and vuln.kev),
        "overdue": bool(f.due_at and f.due_at < now and f.status in OPEN_STATUSES),
    })


@router.get("/findings", response_model=Page[FindingOut])
def list_findings(
    db: Db, paging: Paging, _: Principal = require("findings:read"),
    q: str | None = Query(None, max_length=200), severity: list[str] | None = Query(None),
    status: list[str] | None = Query(None), domain: list[str] | None = Query(None),
    risk_level: list[str] | None = Query(None), asset_id: uuid.UUID | None = None, source: str | None = None,
    owner_user_id: uuid.UUID | None = None, owner_team_id: uuid.UUID | None = None, open_only: bool = False,
    kev: bool = False, overdue: bool = False, unassigned: bool = False, ai_only: bool = False,
    sort: str = "risk_score", order: Literal["asc", "desc"] = "desc",
) -> Page[FindingOut]:
    stmt = (select(Finding, Asset, Vulnerability).join(Asset, Asset.id == Finding.asset_id)
            .outerjoin(Vulnerability, Vulnerability.id == Finding.vulnerability_id))
    if q:
        pattern = f"%{like_escape(q)}%"
        stmt = stmt.where(or_(Finding.title.ilike(pattern), Asset.name.ilike(pattern), Finding.rule_id.ilike(pattern),
                              Vulnerability.external_id.ilike(pattern)))
    for column, values in ((Finding.severity, severity), (Finding.status, status), (Finding.domain, domain),
                           (Finding.risk_level, risk_level)):
        if values:
            stmt = stmt.where(column.in_(values))
    for column, value in ((Finding.asset_id, asset_id), (Finding.source, source),
                          (Finding.owner_user_id, owner_user_id), (Finding.owner_team_id, owner_team_id)):
        if value:
            stmt = stmt.where(column == value)
    if open_only:
        stmt = stmt.where(Finding.status.in_(OPEN_STATUSES))
    if ai_only:
        stmt = stmt.where(Finding.domain.in_(AI_DOMAINS))
    if kev:
        stmt = stmt.where(Vulnerability.kev.is_(True))
    if overdue:
        stmt = stmt.where(Finding.due_at < utcnow(), Finding.status.in_(OPEN_STATUSES))
    if unassigned:
        stmt = stmt.where(Finding.owner_user_id.is_(None), Finding.owner_team_id.is_(None))
    column = SORTABLE.get(sort, Finding.risk_score)
    stmt = stmt.order_by(column.asc().nulls_last() if order == "asc" else column.desc().nulls_last(), Finding.id)
    rows, total = paginate(db, stmt, paging, scalars=False)
    return Page(items=[_out(f, a, v) for f, a, v in rows], total=total, page=paging.page, page_size=paging.page_size)


@router.get("/findings/facets")
def finding_facets(db: Db, _: Principal = require("findings:read")) -> dict:
    def group(column):
        return dict(db.execute(select(column, func.count()).where(Finding.status.in_(OPEN_STATUSES)).group_by(column)).all())

    return {"severity": group(Finding.severity), "risk_level": group(Finding.risk_level), "domain": group(Finding.domain),
            "source": group(Finding.source),
            "status": dict(db.execute(select(Finding.status, func.count()).group_by(Finding.status)).all()),
            "transitions": {k: sorted(v) for k, v in service.TRANSITIONS.items()}}


@router.post("/findings", response_model=FindingOut, status_code=201)
def create_manual_finding(body: ManualFindingIn, db: Db, principal: Principal = require("findings:write")) -> FindingOut:
    asset = db.get(Asset, body.asset_id)
    if asset is None:
        raise ValidationFailed("Asset does not exist")
    finding, _created = service.ingest(db, service.FindingInput(
        asset=asset, source="manual", rule_id=f"manual:{uuid.uuid4().hex[:12]}", domain=body.domain,
        title=body.title, description=body.description, severity=body.severity, confidence=body.confidence,
        remediation=body.remediation, reproduction=body.reproduction, technical_impact=body.technical_impact,
        business_impact=body.business_impact, references=body.references, vulnerability_id=body.cve,
        attributes={"reported_by": principal.email},
    ))
    audit_event(db, principal, "finding.created", entity_type="finding", entity_id=finding.id)
    vuln = db.get(Vulnerability, finding.vulnerability_id) if finding.vulnerability_id else None
    return _out(finding, asset, vuln)


@router.get("/findings/{finding_id}")
def get_finding(finding_id: uuid.UUID, db: Db, _: Principal = require("findings:read")) -> dict:
    f = _get(db, finding_id)
    asset = db.get(Asset, f.asset_id)
    vuln = db.get(Vulnerability, f.vulnerability_id) if f.vulnerability_id else None
    ai = db.get(AIFinding, f.id)
    risk = db.execute(select(RiskScore).where(RiskScore.finding_id == f.id).order_by(RiskScore.calculated_at.desc())
                      .limit(20)).scalars().all()
    evidence = db.execute(select(Evidence).where(Evidence.finding_id == f.id).order_by(Evidence.created_at)).scalars()
    events = db.execute(select(FindingEvent, User.full_name).outerjoin(User, User.id == FindingEvent.actor_user_id)
                        .where(FindingEvent.finding_id == f.id).order_by(FindingEvent.occurred_at)).all()
    tasks = db.execute(select(RemediationTask).where(RemediationTask.finding_id == f.id)).scalars()
    acceptances = db.execute(select(RiskAcceptance).where(RiskAcceptance.finding_id == f.id)
                             .order_by(RiskAcceptance.created_at.desc())).scalars()
    can_retest = False
    if f.assessment_run_id:
        run = db.get(AssessmentRun, f.assessment_run_id)
        can_retest = bool(run and db.get(Assessment, run.assessment_id))
    return {
        **_out(f, asset, vuln).model_dump(),
        "description": f.description, "technical_impact": f.technical_impact, "business_impact": f.business_impact,
        "remediation": f.remediation, "reproduction": f.reproduction, "references": f.references, "cwe": f.cwe,
        "attributes": f.attributes, "resolved_at": f.resolved_at, "assessment_run_id": f.assessment_run_id,
        "can_automated_retest": can_retest, "allowed_transitions": sorted(service.TRANSITIONS.get(f.status, set())),
        "asset": {"id": asset.id, "name": asset.name, "type": asset.type, "identifier": asset.identifier,
                  "exposure": asset.exposure, "criticality": asset.criticality, "environment": asset.environment,
                  "data_sensitivity": asset.data_sensitivity} if asset else None,
        "vulnerability": {
            "external_id": vuln.external_id, "title": vuln.title, "description": vuln.description,
            "cvss_score": vuln.cvss_score, "cvss_vector": vuln.cvss_vector, "cwe_ids": vuln.cwe_ids,
            "epss_score": vuln.epss_score, "epss_percentile": vuln.epss_percentile, "kev": vuln.kev,
            "kev_date_added": vuln.kev_date_added, "kev_due_date": vuln.kev_due_date,
            "exploit_available": vuln.exploit_available, "fixed_versions": vuln.fixed_versions,
            "references": vuln.references, "published_at": vuln.published_at, "source": vuln.source,
        } if vuln else None,
        "ai": {"owasp_llm": ai.owasp_llm, "atlas_technique": ai.atlas_technique, "nist_ai_rmf": ai.nist_ai_rmf,
               "test_id": ai.test_id} if ai else None,
        "risk": {"current": risk[0].breakdown if risk else None,
                 "history": [{"score": r.score, "level": r.level, "calculated_at": r.calculated_at} for r in risk]},
        "evidence": [{"id": e.id, "kind": e.kind, "summary": e.summary, "content": e.content,
                      "has_file": bool(e.storage_key), "content_type": e.content_type, "size_bytes": e.size_bytes,
                      "sha256": e.sha256, "created_at": e.created_at} for e in evidence],
        "timeline": [{"id": e.id, "event_type": e.event_type, "data": e.data, "occurred_at": e.occurred_at,
                      "actor": name} for e, name in events],
        "remediation_tasks": [{"id": t.id, "title": t.title, "status": t.status, "due_at": t.due_at,
                               "assignee_user_id": t.assignee_user_id, "ticket_url": t.ticket_url,
                               "ticket_key": t.ticket_key} for t in tasks],
        "risk_acceptances": [{"id": a.id, "status": a.status, "reason": a.reason, "expires_at": a.expires_at,
                              "compensating_controls": a.compensating_controls, "decided_at": a.decided_at}
                             for a in acceptances],
    }


@router.patch("/findings/{finding_id}", response_model=FindingOut)
def update_finding(finding_id: uuid.UUID, body: FindingPatch, db: Db, principal: Principal = require("findings:write")) -> FindingOut:
    f = _get(db, finding_id)
    fields = body.model_fields_set
    if "owner_user_id" in fields or "owner_team_id" in fields:
        if body.owner_user_id and db.get(User, body.owner_user_id) is None:
            raise ValidationFailed("Owner user does not exist")
        if body.owner_team_id and db.get(Team, body.owner_team_id) is None:
            raise ValidationFailed("Owner team does not exist")
        if "owner_user_id" in fields:
            f.owner_user_id = body.owner_user_id
        if "owner_team_id" in fields:
            f.owner_team_id = body.owner_team_id
        service.add_event(db, f, "assigned", {"owner_user_id": str(f.owner_user_id) if f.owner_user_id else None,
                                              "owner_team_id": str(f.owner_team_id) if f.owner_team_id else None},
                          principal.user_id)
        if f.status in ("new", "triaged") and (f.owner_user_id or f.owner_team_id) and not body.status:
            service.transition(db, f, "assigned", actor_user_id=principal.user_id)
    if "due_at" in fields and body.due_at != f.due_at:
        service.add_event(db, f, "due_date_changed", {"from": str(f.due_at), "to": str(body.due_at)}, principal.user_id)
        f.due_at = body.due_at
    if body.status and body.status != f.status:
        if body.status == "accepted_risk":
            raise ValidationFailed("Use the risk acceptance workflow to accept risk")
        if body.status == "remediated":
            raise ValidationFailed("Findings are marked remediated by a retest or manual verification")
        if body.status == "false_positive" and len(body.note.strip()) < 10:
            raise ValidationFailed("A justification of at least 10 characters is required for false positives")
        service.transition(db, f, body.status, actor_user_id=principal.user_id, note=body.note)
    db.flush()
    audit_event(db, principal, "finding.updated", entity_type="finding", entity_id=f.id,
                data=body.model_dump(exclude_unset=True, mode="json"))
    vuln = db.get(Vulnerability, f.vulnerability_id) if f.vulnerability_id else None
    return _out(f, db.get(Asset, f.asset_id), vuln)


@router.post("/findings/{finding_id}/comments", status_code=201)
def add_comment(finding_id: uuid.UUID, body: CommentIn, db: Db, principal: Principal = require("findings:write")) -> dict:
    f = _get(db, finding_id)
    service.add_event(db, f, "comment", {"body": body.body}, principal.user_id)
    return {"status": "created"}


@router.post("/findings/{finding_id}/retest", status_code=202)
def retest(finding_id: uuid.UUID, db: Db, principal: Principal = require("findings:write", "assessments:run")) -> dict:
    """Re-run the assessment that produced the finding. The finding moves to pending validation
    and is marked remediated only if the re-run no longer observes it."""
    from app.domains.assessments.service import start_run

    f = _get(db, finding_id)
    run = db.get(AssessmentRun, f.assessment_run_id) if f.assessment_run_id else None
    assessment = db.get(Assessment, run.assessment_id) if run else None
    if assessment is None:
        raise Conflict("This finding has no re-runnable assessment; record a manual verification instead")
    if f.status not in OPEN_STATUSES:
        raise Conflict(f"A {f.status} finding cannot be retested")
    if f.status != "pending_validation":
        service.transition(db, f, "pending_validation", actor_user_id=principal.user_id, note="Retest requested",
                           force=True)
    new_run = start_run(db, assessment, principal, retest_of_finding_id=f.id)
    service.add_event(db, f, "retest", {"result": "requested", "run_id": str(new_run.id)}, principal.user_id)
    audit_event(db, principal, "finding.retest_requested", entity_type="finding", entity_id=f.id)
    return {"run_id": new_run.id, "job_id": new_run.job_id}


@router.post("/findings/{finding_id}/verify", response_model=FindingOut)
def manual_verification(finding_id: uuid.UUID, body: VerifyIn, db: Db, principal: Principal = require("findings:write")) -> FindingOut:
    """Record a manual retest result for findings that cannot be re-tested automatically."""
    f = _get(db, finding_id)
    if f.status not in OPEN_STATUSES:
        raise Conflict(f"A {f.status} finding cannot be verified")
    service.add_event(db, f, "retest", {"result": "not_present" if body.result == "fixed" else "still_present",
                                        "manual": True, "note": body.note}, principal.user_id)
    service.transition(db, f, "remediated" if body.result == "fixed" else "in_progress",
                       actor_user_id=principal.user_id, note=body.note, force=True)
    audit_event(db, principal, "finding.verified", entity_type="finding", entity_id=f.id, data={"result": body.result})
    vuln = db.get(Vulnerability, f.vulnerability_id) if f.vulnerability_id else None
    return _out(f, db.get(Asset, f.asset_id), vuln)


@router.post("/findings/{finding_id}/evidence", status_code=201)
async def upload_evidence(
    finding_id: uuid.UUID, db: Db, principal: Principal = require("findings:write"),
    file: UploadFile = File(...), summary: str = Form(..., min_length=3, max_length=500),
) -> dict:
    f = _get(db, finding_id)
    name = (file.filename or "").lower()
    ext = "." + name.rsplit(".", 1)[-1] if "." in name else ""
    if ext not in UPLOAD_TYPES:
        raise ValidationFailed("File type is not allowed", details={"allowed": sorted(UPLOAD_TYPES)})
    limit = get_settings().max_upload_bytes
    data = await file.read(limit + 1)
    if len(data) > limit:
        raise ValidationFailed(f"File exceeds the {limit // (1024 * 1024)} MB limit")
    if not data:
        raise ValidationFailed("File is empty")
    content_type, signatures = UPLOAD_TYPES[ext]
    if signatures and not any(data.startswith(sig) for sig in signatures):
        raise ValidationFailed("File content does not match its extension")
    if not signatures:
        try:
            data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValidationFailed("Text evidence must be UTF-8") from exc
    key = storage.new_key(principal.organization_id, "evidence", ext)
    storage.get_storage().put(key, data, content_type)
    row = Evidence(organization_id=principal.organization_id, finding_id=f.id, kind="file", summary=summary,
                   content={"original_filename": name[-200:]}, storage_key=key, content_type=content_type,
                   size_bytes=len(data), sha256=sha256_hex(data), created_by_user_id=principal.user_id,
                   created_at=utcnow())
    db.add(row)
    db.flush()
    service.add_event(db, f, "evidence_added", {"evidence_id": str(row.id), "summary": summary}, principal.user_id)
    audit_event(db, principal, "evidence.uploaded", entity_type="evidence", entity_id=row.id,
                data={"sha256": row.sha256, "size": row.size_bytes})
    return {"id": row.id, "sha256": row.sha256, "size_bytes": row.size_bytes}


@router.get("/evidence/{evidence_id}/download")
def download_evidence(evidence_id: uuid.UUID, db: Db, principal: Principal = require("findings:read")) -> Response:
    row = db.get(Evidence, evidence_id)
    if row is None or not row.storage_key:
        raise NotFound("Evidence file not found")
    data = storage.read_for_org(principal.organization_id, row.storage_key)
    audit_event(db, principal, "evidence.downloaded", entity_type="evidence", entity_id=row.id)
    ext = row.storage_key.rsplit(".", 1)[-1] if "." in row.storage_key else "bin"
    return Response(content=data, media_type="application/octet-stream", headers={
        "Content-Disposition": f'attachment; filename="evidence-{row.id}.{ext}"', "X-Content-Type-Options": "nosniff",
    })
