"""Findings, evidence, vulnerability catalogue, risk scoring and remediation."""

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, Boolean, Float, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, IdMixin, TenantMixin, TimestampMixin, fk

SEVERITIES = ("critical", "high", "medium", "low", "info")
FINDING_STATUSES = (
    "new", "triaged", "assigned", "in_progress", "pending_validation", "remediated", "accepted_risk",
    "false_positive", "closed",
)
OPEN_STATUSES = ("new", "triaged", "assigned", "in_progress", "pending_validation")
FINDING_DOMAINS = (
    "attack_surface", "vulnerability", "web", "api", "cloud", "identity", "network", "container", "iac",
    "supply_chain", "secrets", "ai_llm", "ai_rag", "ai_agent", "ai_mcp", "ai_model", "ai_infra",
    "shadow_ai", "policy",
)
AI_DOMAINS = ("ai_llm", "ai_rag", "ai_agent", "ai_mcp", "ai_model", "ai_infra", "shadow_ai")
CONFIDENCES = ("confirmed", "firm", "tentative")


class Vulnerability(Base, IdMixin, TimestampMixin):
    """Global vulnerability catalogue entry (CVE, GHSA or OSV id). Not tenant-owned."""

    __tablename__ = "vulnerabilities"

    external_id: Mapped[str] = mapped_column(String(64), unique=True)
    aliases: Mapped[list[str]] = mapped_column(ARRAY(String(64)), default=list, server_default="{}")
    source: Mapped[str] = mapped_column(String(32))
    title: Mapped[str] = mapped_column(String(512), default="", server_default="")
    description: Mapped[str] = mapped_column(Text, default="", server_default="")
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(160))
    cvss_version: Mapped[str | None] = mapped_column(String(8))
    cwe_ids: Mapped[list[str]] = mapped_column(ARRAY(String(24)), default=list, server_default="{}")
    epss_score: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    epss_date: Mapped[datetime | None]
    kev: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false", index=True)
    kev_date_added: Mapped[datetime | None]
    kev_due_date: Mapped[datetime | None]
    kev_ransomware_use: Mapped[bool | None] = mapped_column(Boolean)
    exploit_available: Mapped[bool | None] = mapped_column(Boolean)
    affected: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    fixed_versions: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    references: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    remediation: Mapped[str] = mapped_column(Text, default="", server_default="")
    published_at: Mapped[datetime | None]
    modified_at: Mapped[datetime | None]


class Finding(Base, IdMixin, TenantMixin, TimestampMixin):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("organization_id", "dedup_key"),
        Index("ix_findings_org_status_sev", "organization_id", "status", "severity"),
        Index("ix_findings_org_domain", "organization_id", "domain"),
        Index("ix_findings_title_trgm", "title", postgresql_using="gin", postgresql_ops={"title": "gin_trgm_ops"}),
    )

    asset_id: Mapped[uuid.UUID] = fk("assets.id")
    vulnerability_id: Mapped[uuid.UUID | None] = fk("vulnerabilities.id", ondelete="SET NULL", nullable=True)
    assessment_run_id: Mapped[uuid.UUID | None] = fk("assessment_runs.id", ondelete="SET NULL", nullable=True)
    dedup_key: Mapped[str] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(64))  # producing engine or scanner
    rule_id: Mapped[str] = mapped_column(String(200))
    domain: Mapped[str] = mapped_column(String(24))
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str] = mapped_column(Text, default="", server_default="")
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[str] = mapped_column(String(16), default="firm", server_default="firm")
    status: Mapped[str] = mapped_column(String(24), default="new", server_default="new")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, server_default="0", index=True)
    risk_level: Mapped[str] = mapped_column(String(16), default="info", server_default="info")
    technical_impact: Mapped[str] = mapped_column(Text, default="", server_default="")
    business_impact: Mapped[str] = mapped_column(Text, default="", server_default="")
    remediation: Mapped[str] = mapped_column(Text, default="", server_default="")
    reproduction: Mapped[str] = mapped_column(Text, default="", server_default="")
    references: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    cwe: Mapped[str | None] = mapped_column(String(24))
    attributes: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    owner_user_id: Mapped[uuid.UUID | None] = fk("users.id", ondelete="SET NULL", nullable=True)
    owner_team_id: Mapped[uuid.UUID | None] = fk("teams.id", ondelete="SET NULL", nullable=True)
    due_at: Mapped[datetime | None]
    first_seen_at: Mapped[datetime]
    last_seen_at: Mapped[datetime]
    resolved_at: Mapped[datetime | None]


class AIFinding(Base, TenantMixin):
    """AI-specific taxonomy for a finding (1:1 extension of Finding)."""

    __tablename__ = "ai_findings"

    finding_id: Mapped[uuid.UUID] = fk("findings.id", primary_key=True, index=False)
    owasp_llm: Mapped[str | None] = mapped_column(String(16), index=True)  # e.g. LLM01:2025
    atlas_technique: Mapped[str | None] = mapped_column(String(24))  # e.g. AML.T0051
    nist_ai_rmf: Mapped[str | None] = mapped_column(String(32))  # e.g. MEASURE 2.7
    test_id: Mapped[str | None] = mapped_column(String(64))


class Evidence(Base, IdMixin, TenantMixin):
    __tablename__ = "evidence"

    finding_id: Mapped[uuid.UUID | None] = fk("findings.id", nullable=True)
    assessment_run_id: Mapped[uuid.UUID | None] = fk("assessment_runs.id", ondelete="SET NULL", nullable=True)
    kind: Mapped[str] = mapped_column(String(32))  # http_exchange | dns | tls | scanner_output | llm_exchange | file | config | note
    summary: Mapped[str] = mapped_column(String(1000))
    # Small structured evidence is stored inline (already redacted); larger artifacts go to
    # object storage and are referenced by storage_key.
    content: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    storage_key: Mapped[str | None] = mapped_column(String(300))
    content_type: Mapped[str | None] = mapped_column(String(120))
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    sha256: Mapped[str | None] = mapped_column(String(64))
    created_by_user_id: Mapped[uuid.UUID | None] = fk("users.id", ondelete="SET NULL", nullable=True, index=False)
    created_at: Mapped[datetime]


class FindingEvent(Base, IdMixin, TenantMixin):
    """Finding timeline: status changes, assignment, comments, retests."""

    __tablename__ = "finding_events"
    __table_args__ = (Index("ix_finding_events_finding_time", "finding_id", "occurred_at"),)

    finding_id: Mapped[uuid.UUID] = fk("findings.id", index=False)
    actor_user_id: Mapped[uuid.UUID | None] = fk("users.id", ondelete="SET NULL", nullable=True, index=False)
    event_type: Mapped[str] = mapped_column(String(32))
    data: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    occurred_at: Mapped[datetime]


class RiskScore(Base, IdMixin, TenantMixin):
    """Risk score history with the full factor breakdown used to produce it."""

    __tablename__ = "risk_scores"
    __table_args__ = (Index("ix_risk_scores_finding_time", "finding_id", "calculated_at"),)

    finding_id: Mapped[uuid.UUID] = fk("findings.id", index=False)
    score: Mapped[float] = mapped_column(Float)
    level: Mapped[str] = mapped_column(String(16))
    breakdown: Mapped[dict] = mapped_column(JSONB)
    policy_version: Mapped[int] = mapped_column(Integer, default=1)
    calculated_at: Mapped[datetime]


class RiskAcceptance(Base, IdMixin, TenantMixin, TimestampMixin):
    __tablename__ = "risk_acceptances"

    finding_id: Mapped[uuid.UUID] = fk("findings.id")
    owner_user_id: Mapped[uuid.UUID] = fk("users.id", ondelete="RESTRICT")
    requested_by_user_id: Mapped[uuid.UUID] = fk("users.id", ondelete="RESTRICT", index=False)
    reason: Mapped[str] = mapped_column(Text)
    compensating_controls: Mapped[str] = mapped_column(Text, default="", server_default="")
    status: Mapped[str] = mapped_column(String(16), default="pending", server_default="pending")
    decided_by_user_id: Mapped[uuid.UUID | None] = fk("users.id", ondelete="SET NULL", nullable=True, index=False)
    decided_at: Mapped[datetime | None]
    decision_note: Mapped[str] = mapped_column(Text, default="", server_default="")
    expires_at: Mapped[datetime]


class RemediationTask(Base, IdMixin, TenantMixin, TimestampMixin):
    __tablename__ = "remediation_tasks"

    finding_id: Mapped[uuid.UUID] = fk("findings.id")
    title: Mapped[str] = mapped_column(String(512))
    instructions: Mapped[str] = mapped_column(Text, default="", server_default="")
    status: Mapped[str] = mapped_column(String(24), default="open", server_default="open")
    priority: Mapped[str] = mapped_column(String(16), default="medium", server_default="medium")
    assignee_user_id: Mapped[uuid.UUID | None] = fk("users.id", ondelete="SET NULL", nullable=True)
    team_id: Mapped[uuid.UUID | None] = fk("teams.id", ondelete="SET NULL", nullable=True)
    due_at: Mapped[datetime | None]
    completed_at: Mapped[datetime | None]
    verified_at: Mapped[datetime | None]
    verified_by_user_id: Mapped[uuid.UUID | None] = fk("users.id", ondelete="SET NULL", nullable=True, index=False)
    overdue_notified_at: Mapped[datetime | None]
    ticket_system: Mapped[str | None] = mapped_column(String(32))
    ticket_key: Mapped[str | None] = mapped_column(String(120))
    ticket_url: Mapped[str | None] = mapped_column(String(1000))
    created_by_user_id: Mapped[uuid.UUID | None] = fk("users.id", ondelete="SET NULL", nullable=True, index=False)
