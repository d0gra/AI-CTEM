"""Report datasets and renderers (JSON, CSV, XLSX, PDF).

A report is built once as a `ReportData` structure from live tenant data and then rendered.
Every report states its generation time, scope, methodology and limitations.
"""

import csv
import io
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models import (
    AIAssessmentTest,
    AIAsset,
    AIFinding,
    AssessmentRun,
    Asset,
    AttackPath,
    Finding,
    Organization,
    Policy,
    PolicyEvaluation,
    RemediationTask,
    Vulnerability,
)
from app.models.asset import AI_ASSET_TYPES
from app.models.finding import AI_DOMAINS, OPEN_STATUSES

FORMATS = {"json": "application/json", "csv": "text/csv", "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
           "pdf": "application/pdf"}
MAX_ROWS = 20000
PDF_ROWS_PER_SECTION = 60

METHODOLOGY = ("Findings are produced by the platform's assessment engines and by imported scanner results, de-duplicated per asset, "
               "source and rule. Risk scores are computed by the unified risk engine from technical severity, exploitation intelligence "
               "(CISA KEV, EPSS), asset exposure, asset criticality and data sensitivity, evidence confidence, attack-path position and AI-specific "
               "factors. Each finding links to stored evidence in the platform.")
LIMITATIONS = ("This report reflects only assets and findings known to the platform at generation time. Coverage is limited to configured "
               "integrations and authorized scope; absence of a finding is not evidence of absence of a weakness. Findings with tentative "
               "confidence have not been verified by exploitation. Shadow-AI visibility is limited to analysed repositories, probed endpoints "
               "and registered assets.")


@dataclass
class Section:
    title: str
    columns: list[str]
    rows: list[list]
    note: str = ""


@dataclass
class ReportData:
    type: str
    title: str
    organization: str
    generated_at: str
    period: str
    scope: str
    methodology: str = METHODOLOGY
    limitations: str = LIMITATIONS
    summary: list[list] = field(default_factory=list)
    sections: list[Section] = field(default_factory=list)


def _window(stmt, column, date_from: datetime | None, date_to: datetime | None):
    if date_from:
        stmt = stmt.where(column >= date_from)
    if date_to:
        stmt = stmt.where(column <= date_to)
    return stmt


def _iso(value) -> str:
    return value.strftime("%Y-%m-%d") if isinstance(value, datetime) else ("" if value is None else str(value))


FINDING_COLUMNS = ["Finding ID", "Title", "Risk level", "Risk score", "Severity", "Confidence", "Status", "Domain", "Asset", "Asset type",
                   "Exposure", "Vulnerability", "KEV", "Source", "First seen", "Due", "Remediation"]


def _finding_rows(db: Session, date_from, date_to, *where) -> list[list]:
    stmt = (select(Finding, Asset, Vulnerability).join(Asset, Asset.id == Finding.asset_id)
            .outerjoin(Vulnerability, Vulnerability.id == Finding.vulnerability_id).where(*where)
            .order_by(Finding.risk_score.desc()).limit(MAX_ROWS))
    stmt = _window(stmt, Finding.first_seen_at, date_from, date_to)
    return [[str(f.id), f.title, f.risk_level, f.risk_score, f.severity, f.confidence, f.status, f.domain, a.name, a.type, a.exposure,
             v.external_id if v else "", "yes" if v and v.kev else "", f.source, _iso(f.first_seen_at), _iso(f.due_at), f.remediation[:500]]
            for f, a, v in db.execute(stmt).all()]


def _count(db: Session, model, *where) -> int:
    return db.execute(select(func.count()).select_from(model).where(*where)).scalar_one()


def _group(db: Session, column, *where) -> dict:
    return dict(db.execute(select(column, func.count()).where(*where).group_by(column)).all())


def _levels(db: Session, *where) -> list[list]:
    by = _group(db, Finding.risk_level, Finding.status.in_(OPEN_STATUSES), *where)
    return [[f"Open findings: {level}", by.get(level, 0)] for level in ("critical", "high", "medium", "low", "info")]


def _attack_path_section(db: Session, *where) -> Section:
    paths = db.execute(select(AttackPath).where(AttackPath.status == "active", *where).order_by(AttackPath.score.desc()).limit(500)).scalars()
    return Section("Attack paths", ["Path", "Classification", "Severity", "Score", "Steps", "Involves AI", "Business impact"],
                   [[p.title, p.classification, p.severity, p.score, len(p.edges), "yes" if p.involves_ai else "", p.business_impact] for p in paths],
                   "Verified: every step is backed by a confirmed high-severity finding and an authoritative relationship. "
                   "Probable: backed by firm evidence. Theoretical: relationship exists without a demonstrated weakness.")


def build(db: Session, organization_id, report_type: str, date_from: datetime | None, date_to: datetime | None) -> ReportData:
    rows: Any
    org = db.get(Organization, organization_id)
    now = utcnow()
    period = f"{_iso(date_from) or 'beginning'} to {_iso(date_to) or _iso(now)} (by finding first-seen date)"
    data = ReportData(type=report_type, title=REPORT_TYPES[report_type], organization=org.name if org else "", period=period,
                      generated_at=now.strftime("%Y-%m-%d %H:%M UTC"),
                      scope=f"All assets and findings recorded for {org.name if org else 'the organization'} in the platform.")
    open_ = Finding.status.in_(OPEN_STATUSES)
    active = Asset.status != "retired"

    if report_type == "executive":
        data.summary = [["Assets", _count(db, Asset, active)], ["Internet-exposed assets", _count(db, Asset, active, Asset.exposure == "internet")],
                        *_levels(db), ["Active attack paths", _count(db, AttackPath, AttackPath.status == "active")],
                        ["Critical/high attack paths", _count(db, AttackPath, AttackPath.status == "active", AttackPath.severity.in_(("critical", "high")))],
                        ["Findings past SLA", _count(db, Finding, open_, Finding.due_at < now)],
                        ["AI assets", _count(db, Asset, active, Asset.type.in_(AI_ASSET_TYPES))],
                        ["Open AI findings", _count(db, Finding, open_, Finding.domain.in_(AI_DOMAINS))]]
        by_domain = _group(db, Finding.domain, open_)
        data.sections = [
            Section("Open findings by domain", ["Domain", "Open findings"], sorted(([k, v] for k, v in by_domain.items()), key=lambda r: -r[1])),
            Section("Top risks", FINDING_COLUMNS, _finding_rows(db, date_from, date_to, open_)[:25]),
            _attack_path_section(db),
        ]
    elif report_type in ("technical", "vulnerability", "attack_surface", "cloud", "ai_security"):
        filters = {"technical": (), "vulnerability": (Finding.vulnerability_id.isnot(None),),
                   "attack_surface": (Finding.domain.in_(("attack_surface", "web", "api", "network")),),
                   "cloud": (Finding.domain.in_(("cloud", "identity", "container", "iac")),),
                   "ai_security": (Finding.domain.in_(AI_DOMAINS),)}[report_type]
        data.summary = _levels(db, *filters)
        data.sections = [Section("Findings", FINDING_COLUMNS, _finding_rows(db, date_from, date_to, *filters))]
        if report_type == "vulnerability":
            rows = db.execute(
                select(Vulnerability, func.count(func.distinct(Finding.asset_id))).join(Finding, Finding.vulnerability_id == Vulnerability.id)
                .where(open_).group_by(Vulnerability.id).order_by(Vulnerability.kev.desc(), Vulnerability.epss_score.desc().nulls_last()).limit(2000)).all()
            data.sections.insert(0, Section("Vulnerabilities affecting assets", ["ID", "CVSS", "EPSS", "EPSS percentile", "KEV", "KEV due", "Affected assets", "Title"],
                                            [[v.external_id, v.cvss_score, v.epss_score, v.epss_percentile, "yes" if v.kev else "", _iso(v.kev_due_date), n, v.title] for v, n in rows]))
        if report_type == "attack_surface":
            assets = db.execute(select(Asset).where(active, Asset.exposure == "internet").order_by(Asset.risk_score.desc()).limit(MAX_ROWS)).scalars()
            data.sections.insert(0, Section("Internet-exposed assets", ["Asset", "Type", "Identifier", "Environment", "Risk score", "First seen", "Last seen", "Sources"],
                                            [[a.name, a.type, a.identifier, a.environment, a.risk_score, _iso(a.first_seen_at), _iso(a.last_seen_at), ", ".join(a.discovery_sources)] for a in assets]))
        if report_type == "ai_security":
            rows = db.execute(select(Asset, AIAsset).outerjoin(AIAsset, AIAsset.asset_id == Asset.id).where(active, Asset.type.in_(AI_ASSET_TYPES))
                              .order_by(Asset.risk_score.desc()).limit(MAX_ROWS)).all()
            data.summary += [["AI assets", len(rows)], ["Unapproved or unknown approval", sum(1 for _a, x in rows if not x or x.approval_status != "approved")],
                             ["AI assets without owner", sum(1 for a, _x in rows if not (a.owner_user_id or a.owner_team_id))]]
            data.sections.insert(0, Section("AI asset inventory", ["Asset", "Type", "Provider", "Approval", "Exposure", "Environment", "Owner assigned", "Auth required", "Risk score"],
                                            [[a.name, a.type, x.provider if x else "", x.approval_status if x else "unknown", a.exposure, a.environment,
                                              "yes" if a.owner_user_id or a.owner_team_id else "no", "" if not x or x.auth_required is None else str(x.auth_required), a.risk_score] for a, x in rows]))
            taxonomy = db.execute(select(AIFinding.owasp_llm, func.count()).join(Finding, Finding.id == AIFinding.finding_id)
                                  .where(open_, AIFinding.owasp_llm.isnot(None)).group_by(AIFinding.owasp_llm).order_by(AIFinding.owasp_llm)).all()
            data.sections.append(Section("Open AI findings by OWASP LLM Top 10 (2025)", ["Category", "Open findings"], [list(r) for r in taxonomy]))
            data.sections.append(_attack_path_section(db, AttackPath.involves_ai.is_(True)))
    elif report_type == "ai_redteam":
        stmt = (select(AIAssessmentTest, AssessmentRun).join(AssessmentRun, AssessmentRun.id == AIAssessmentTest.assessment_run_id)
                .where(AssessmentRun.dry_run.is_(False)).order_by(AssessmentRun.created_at.desc(), AIAssessmentTest.test_id).limit(MAX_ROWS))
        stmt = _window(stmt, AssessmentRun.created_at, date_from, date_to)
        rows = db.execute(stmt).all()
        executed = [t for t, _ in rows if t.execution_status == "executed"]
        data.summary = [["Tests recorded", len(rows)], ["Executed", len(executed)], ["Vulnerable", sum(t.outcome == "vulnerable" for t in executed)],
                        ["Not vulnerable", sum(t.outcome == "not_vulnerable" for t in executed)],
                        ["Skipped or errored", len(rows) - len(executed)]]
        data.methodology = ("Deterministic adversarial tests from the platform catalogue. A test is recorded as vulnerable only when a unique marker, "
                            "planted canary or forbidden tool call appears in the target's response. Tools requested by the target are never executed. "
                            "Each test ran under a recorded authorization, request budget and rate limit.")
        data.sections = [Section("Test results", ["Run date", "Test ID", "Threat category", "OWASP LLM", "MITRE ATLAS", "Status", "Outcome", "Confidence",
                                                  "Severity", "Reproduced", "Retest", "Scope", "Objective", "Observed behaviour", "Remediation"],
                                 [[_iso(r.created_at), t.test_id, t.threat_category, t.owasp_llm, t.atlas_technique or "", t.execution_status, t.outcome or "",
                                   t.confidence or "", t.severity, f"{t.reproduced}/{t.attempts}", t.retest_result or "", t.scope, t.objective,
                                   t.observed_behavior, t.remediation] for t, r in rows])]
    elif report_type == "compliance":
        latest = (select(PolicyEvaluation.policy_id, func.max(PolicyEvaluation.evaluated_at).label("at")).group_by(PolicyEvaluation.policy_id).subquery())
        rows = db.execute(select(Policy, PolicyEvaluation).outerjoin(latest, latest.c.policy_id == Policy.id)
                          .outerjoin(PolicyEvaluation, (PolicyEvaluation.policy_id == Policy.id) & (PolicyEvaluation.evaluated_at == latest.c.at))
                          .order_by(Policy.name)).all()
        evaluated = [e for _p, e in rows if e is not None and e.status != "not_applicable"]
        data.summary = [["Policies", len(rows)], ["Compliant", sum(e.status == "compliant" for e in evaluated)],
                        ["Non-compliant", sum(e.status == "non_compliant" for e in evaluated)],
                        ["Never evaluated", sum(1 for _p, e in rows if e is None)]]
        data.sections = [
            Section("Policy compliance", ["Policy", "Severity", "Applies to", "Status", "In scope", "Passed", "Failed", "Exempt", "Evaluated", "Framework references"],
                    [[p.name, p.severity, p.entity_type, e.status if e else "not evaluated", e.total if e else "", e.passed if e else "", e.failed if e else "",
                      e.exempt if e else "", _iso(e.evaluated_at) if e else "", "; ".join(p.framework_refs or [])] for p, e in rows]),
            Section("Violations", ["Policy", "Entity", "Observed values"],
                    [[p.name, v.get("label"), json.dumps(v.get("observed"), default=str)] for p, e in rows if e for v in (e.violations or [])][:MAX_ROWS]),
        ]
        data.methodology = "Each policy is a rule evaluated against asset or finding attributes. Results shown are from the most recent evaluation of each policy."
    elif report_type == "remediation":
        stmt = (select(RemediationTask, Finding).join(Finding, Finding.id == RemediationTask.finding_id).order_by(RemediationTask.due_at.asc().nulls_last()).limit(MAX_ROWS))
        rows = db.execute(_window(stmt, RemediationTask.created_at, date_from, date_to)).all()
        data.summary = [["Tasks", len(rows)], ["Open", sum(t.status in ("open", "in_progress", "pending_validation") for t, _ in rows)],
                        ["Verified complete", sum(t.status == "done" for t, _ in rows)],
                        ["Overdue", sum(bool(t.due_at and t.due_at < now and t.status in ("open", "in_progress")) for t, _ in rows)],
                        ["Findings past SLA", _count(db, Finding, open_, Finding.due_at < now)],
                        ["Findings pending validation", _count(db, Finding, Finding.status == "pending_validation")]]
        data.sections = [
            Section("Remediation tasks", ["Task", "Status", "Priority", "Finding", "Finding status", "Risk level", "Due", "Verified", "Ticket"],
                    [[t.title, t.status, t.priority, f.title, f.status, f.risk_level, _iso(t.due_at), _iso(t.verified_at), t.ticket_url or ""] for t, f in rows]),
            Section("Findings past SLA", FINDING_COLUMNS, _finding_rows(db, None, None, open_, Finding.due_at < now)),
        ]
    elif report_type == "asset_inventory":
        assets = list(db.execute(select(Asset).where(active).order_by(Asset.type, Asset.name).limit(MAX_ROWS)).scalars())
        by_type = _group(db, Asset.type, active)
        data.summary = [["Assets", sum(by_type.values())], ["Internet-exposed", _count(db, Asset, active, Asset.exposure == "internet")],
                        ["Without owner", _count(db, Asset, active, Asset.owner_user_id.is_(None), Asset.owner_team_id.is_(None))]]
        data.sections = [
            Section("Assets by type", ["Type", "Count"], sorted(([k, v] for k, v in by_type.items()), key=lambda r: -r[1])),
            Section("Asset inventory", ["Name", "Type", "Identifier", "Environment", "Exposure", "Criticality", "Data sensitivity", "Owner assigned",
                                        "Risk score", "First seen", "Last seen", "Discovery sources", "Tags"],
                    [[a.name, a.type, a.identifier, a.environment, a.exposure, a.criticality, a.data_sensitivity,
                      "yes" if a.owner_user_id or a.owner_team_id else "no", a.risk_score, _iso(a.first_seen_at), _iso(a.last_seen_at),
                      ", ".join(a.discovery_sources), ", ".join(a.tags)] for a in assets]),
        ]
    return data


REPORT_TYPES = {
    "executive": "Executive risk report", "technical": "Technical assessment report", "vulnerability": "Vulnerability report",
    "attack_surface": "Attack surface report", "cloud": "Cloud security report", "ai_security": "AI security report",
    "ai_redteam": "AI red team report", "compliance": "Compliance report", "remediation": "Remediation report",
    "asset_inventory": "Asset inventory report",
}


def _safe_cell(value):
    """Neutralise spreadsheet formula injection in exported text cells."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return "" if value is None else value


def render_json(data: ReportData) -> bytes:
    return json.dumps(asdict(data), indent=2, default=str).encode()


def render_csv(data: ReportData) -> bytes:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerows([["Report", data.title], ["Organization", data.organization], ["Generated", data.generated_at], ["Period", data.period],
                      ["Scope", data.scope], ["Methodology", data.methodology], ["Limitations", data.limitations], []])
    writer.writerows([[_safe_cell(k), v] for k, v in data.summary])
    for section in data.sections:
        writer.writerows([[], [f"# {section.title}"], section.columns])
        writer.writerows([[_safe_cell(c) for c in row] for row in section.rows])
    return out.getvalue().encode("utf-8-sig")


def render_xlsx(data: ReportData) -> bytes:
    from openpyxl import Workbook
    from openpyxl.styles import Font

    wb = Workbook()
    ws = wb.active
    ws.title = "Summary"
    bold = Font(bold=True)
    for label, value in (("Report", data.title), ("Organization", data.organization), ("Generated", data.generated_at), ("Period", data.period),
                         ("Scope", data.scope), ("Methodology", data.methodology), ("Limitations", data.limitations)):
        ws.append([label, value])
        ws.cell(row=ws.max_row, column=1).font = bold
    ws.append([])
    for label, value in data.summary:
        ws.append([_safe_cell(label), value])
    ws.column_dimensions["A"].width, ws.column_dimensions["B"].width = 34, 90
    used = {"Summary"}
    for section in data.sections:
        name = "".join(ch for ch in section.title if ch not in '[]:*?/\\')[:31] or "Sheet"
        while name in used:
            name = name[:28] + f"_{len(used)}"
        used.add(name)
        sheet = wb.create_sheet(name)
        sheet.append(section.columns)
        for cell in sheet[1]:
            cell.font = bold
        for row in section.rows:
            sheet.append([_safe_cell(c) if not isinstance(c, int | float) else c for c in row])
        sheet.freeze_panes = "A2"
        for index, column in enumerate(section.columns, start=1):
            sheet.column_dimensions[sheet.cell(row=1, column=index).column_letter].width = min(60, max(12, len(column) + 4))
    buffer = io.BytesIO()
    wb.save(buffer)
    return buffer.getvalue()


def render_pdf(data: ReportData) -> bytes:
    from xml.sax.saxutils import escape

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    styles = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=styles["BodyText"], fontSize=8.5, leading=11)
    cell = ParagraphStyle("cell", parent=body, fontSize=7, leading=8.5)
    head = ParagraphStyle("head", parent=cell, textColor=colors.white, fontName="Helvetica-Bold")
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=12, spaceBefore=10)
    buffer = io.BytesIO()
    page = landscape(A4)
    doc = SimpleDocTemplate(buffer, pagesize=page, leftMargin=14 * mm, rightMargin=14 * mm, topMargin=14 * mm, bottomMargin=14 * mm,
                            title=data.title, author="CTEM Platform")
    width = page[0] - 28 * mm

    def footer(canvas, _doc):
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.grey)
        canvas.drawString(14 * mm, 8 * mm, f"{data.title} - {data.organization} - generated {data.generated_at} - Confidential")
        canvas.drawRightString(page[0] - 14 * mm, 8 * mm, f"Page {canvas.getPageNumber()}")

    story = [Paragraph(escape(data.title), styles["Title"]),
             Paragraph(f"<b>{escape(data.organization)}</b> &nbsp; Generated {escape(data.generated_at)} &nbsp; Period: {escape(data.period)}", body),
             Spacer(1, 6), Paragraph("Scope", h2), Paragraph(escape(data.scope), body),
             Paragraph("Methodology", h2), Paragraph(escape(data.methodology), body),
             Paragraph("Limitations", h2), Paragraph(escape(data.limitations), body)]
    grid = TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2a3c")), ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#c5ccd6")),
                       ("VALIGN", (0, 0), (-1, -1), "TOP"), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f6f9")])])
    if data.summary:
        story += [Paragraph("Summary", h2)]
        table = Table([[Paragraph("Metric", head), Paragraph("Value", head)]] + [[Paragraph(escape(str(k)), cell), Paragraph(escape(str(v)), cell)] for k, v in data.summary],
                      colWidths=[90 * mm, 40 * mm])
        table.setStyle(grid)
        story.append(table)
    for section in data.sections:
        story.append(Paragraph(escape(section.title), h2))
        if section.note:
            story.append(Paragraph(escape(section.note), body))
        if not section.rows:
            story.append(Paragraph("No records.", body))
            continue
        columns = section.columns[:10]
        rows = [[Paragraph(escape(c), head) for c in columns]]
        for row in section.rows[:PDF_ROWS_PER_SECTION]:
            rows.append([Paragraph(escape(str("" if v is None else v))[:300], cell) for v in row[:10]])
        table = Table(rows, colWidths=[width / len(columns)] * len(columns), repeatRows=1)
        table.setStyle(grid)
        story.append(table)
        omitted = []
        if len(section.rows) > PDF_ROWS_PER_SECTION:
            omitted.append(f"showing the first {PDF_ROWS_PER_SECTION} of {len(section.rows)} rows")
        if len(section.columns) > 10:
            omitted.append(f"{len(section.columns) - 10} columns omitted")
        if omitted:
            story.append(Paragraph(f"PDF view: {'; '.join(omitted)}. The XLSX, CSV and JSON formats contain the complete data.", body))
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()


RENDERERS = {"json": render_json, "csv": render_csv, "xlsx": render_xlsx, "pdf": render_pdf}
