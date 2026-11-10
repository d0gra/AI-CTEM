"""AI security posture: AI asset extensions, detected integrations, red-team assessments."""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, IdMixin, TenantMixin, TimestampMixin, fk

APPROVAL_STATES = ("approved", "unapproved", "under_review", "unknown")
AUTONOMY_LEVELS = ("human_in_the_loop", "supervised", "autonomous", "unknown")


class AIAsset(Base, TenantMixin, TimestampMixin):
    """AI-specific posture attributes for an asset (1:1 extension of Asset)."""

    __tablename__ = "ai_assets"

    asset_id: Mapped[uuid.UUID] = fk("assets.id", primary_key=True, index=False)
    provider: Mapped[str | None] = mapped_column(String(48), index=True)
    framework: Mapped[str | None] = mapped_column(String(48))
    approval_status: Mapped[str] = mapped_column(String(16), default="unknown", server_default="unknown")
    managed: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    auth_required: Mapped[bool | None] = mapped_column(Boolean)
    rate_limited: Mapped[bool | None] = mapped_column(Boolean)
    processes_sensitive_data: Mapped[bool | None] = mapped_column(Boolean)
    tenant_isolation: Mapped[str | None] = mapped_column(String(24))  # enforced | not_enforced | not_applicable


class AIModel(Base, TenantMixin, TimestampMixin):
    __tablename__ = "ai_models"

    asset_id: Mapped[uuid.UUID] = fk("assets.id", primary_key=True, index=False)
    model_name: Mapped[str] = mapped_column(String(300))
    version: Mapped[str | None] = mapped_column(String(120))
    artifact_format: Mapped[str | None] = mapped_column(String(32))  # pickle | safetensors | gguf | onnx | ...
    source_uri: Mapped[str | None] = mapped_column(String(1024))
    sha256: Mapped[str | None] = mapped_column(String(64))
    size_bytes: Mapped[int | None] = mapped_column(Integer)
    provenance_verified: Mapped[bool | None] = mapped_column(Boolean)
    provenance_detail: Mapped[str] = mapped_column(Text, default="", server_default="")
    license: Mapped[str | None] = mapped_column(String(120))
    last_scanned_at: Mapped[datetime | None]


class AIAgent(Base, TenantMixin, TimestampMixin):
    __tablename__ = "ai_agents"

    asset_id: Mapped[uuid.UUID] = fk("assets.id", primary_key=True, index=False)
    autonomy_level: Mapped[str] = mapped_column(String(24), default="unknown", server_default="unknown")
    human_approval_required: Mapped[bool | None] = mapped_column(Boolean)
    persistent_memory: Mapped[bool | None] = mapped_column(Boolean)
    can_delegate: Mapped[bool | None] = mapped_column(Boolean)
    processes_untrusted_input: Mapped[bool | None] = mapped_column(Boolean)
    identity_asset_id: Mapped[uuid.UUID | None] = fk("assets.id", ondelete="SET NULL", nullable=True)
    # Declared tools: [{name, description, capabilities: [...], requires_approval: bool}]
    tools: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")


class MCPServer(Base, TenantMixin, TimestampMixin):
    __tablename__ = "mcp_servers"

    asset_id: Mapped[uuid.UUID] = fk("assets.id", primary_key=True, index=False)
    transport: Mapped[str] = mapped_column(String(24))  # stdio | streamable_http | sse
    endpoint: Mapped[str | None] = mapped_column(String(1024))
    command: Mapped[str | None] = mapped_column(String(1024))
    auth_type: Mapped[str] = mapped_column(String(24), default="unknown", server_default="unknown")
    uses_tls: Mapped[bool | None] = mapped_column(Boolean)
    config_source: Mapped[str | None] = mapped_column(String(1024))
    server_info: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    tools: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    last_probed_at: Mapped[datetime | None]


class AIIntegration(Base, IdMixin, TenantMixin, TimestampMixin):
    """An observed use of an AI provider or framework inside a source asset (usually a repo)."""

    __tablename__ = "ai_integrations"
    __table_args__ = (
        UniqueConstraint("organization_id", "source_asset_id", "provider", "detection_method", "location"),
    )

    source_asset_id: Mapped[uuid.UUID] = fk("assets.id")
    ai_asset_id: Mapped[uuid.UUID | None] = fk("assets.id", ondelete="SET NULL", nullable=True)
    provider: Mapped[str] = mapped_column(String(48))
    category: Mapped[str] = mapped_column(String(24))  # provider | framework | vector_db | serving | mcp
    package: Mapped[str | None] = mapped_column(String(200))
    version: Mapped[str | None] = mapped_column(String(64))
    detection_method: Mapped[str] = mapped_column(String(24))  # dependency | import | config | secret | endpoint
    location: Mapped[str] = mapped_column(String(700))
    first_seen_at: Mapped[datetime]
    last_seen_at: Mapped[datetime]


class AIAssessment(Base, TenantMixin, TimestampMixin):
    """Authorization and safety envelope for an AI red-team assessment (1:1 with Assessment)."""

    __tablename__ = "ai_assessments"

    assessment_id: Mapped[uuid.UUID] = fk("assessments.id", primary_key=True, index=False)
    target_asset_id: Mapped[uuid.UUID] = fk("assets.id")
    integration_id: Mapped[uuid.UUID | None] = fk("integrations.id", ondelete="SET NULL", nullable=True)
    profiles: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    authorization_statement: Mapped[str] = mapped_column(Text)
    authorized_by_user_id: Mapped[uuid.UUID] = fk("users.id", ondelete="RESTRICT", index=False)
    authorized_at: Mapped[datetime]
    authorization_expires_at: Mapped[datetime]
    request_budget: Mapped[int] = mapped_column(Integer, default=100)
    rate_limit_per_minute: Mapped[int] = mapped_column(Integer, default=20)
    canary_token: Mapped[str] = mapped_column(String(80))


class AIAssessmentTest(Base, IdMixin, TenantMixin):
    """One executed (or planned, in dry-run) red-team test case and its recorded outcome."""

    __tablename__ = "ai_assessment_tests"
    __table_args__ = (Index("ix_ai_tests_run", "assessment_run_id", "test_id"),)

    assessment_run_id: Mapped[uuid.UUID] = fk("assessment_runs.id", index=False)
    test_id: Mapped[str] = mapped_column(String(64))
    profile: Mapped[str] = mapped_column(String(48))
    threat_category: Mapped[str] = mapped_column(String(120))
    owasp_llm: Mapped[str | None] = mapped_column(String(16))
    atlas_technique: Mapped[str | None] = mapped_column(String(24))
    nist_ai_rmf: Mapped[str | None] = mapped_column(String(32))
    objective: Mapped[str] = mapped_column(Text)
    preconditions: Mapped[str] = mapped_column(Text, default="", server_default="")
    scope: Mapped[str] = mapped_column(Text, default="", server_default="")
    procedure: Mapped[str] = mapped_column(Text)
    execution_status: Mapped[str] = mapped_column(String(16))  # planned | executed | skipped | error | cancelled
    outcome: Mapped[str | None] = mapped_column(String(16))  # vulnerable | not_vulnerable | inconclusive
    observed_behavior: Mapped[str] = mapped_column(Text, default="", server_default="")
    confidence: Mapped[str | None] = mapped_column(String(16))
    severity: Mapped[str] = mapped_column(String(16))
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    reproduced: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    remediation: Mapped[str] = mapped_column(Text, default="", server_default="")
    evidence_id: Mapped[uuid.UUID | None] = fk("evidence.id", ondelete="SET NULL", nullable=True, index=False)
    finding_id: Mapped[uuid.UUID | None] = fk("findings.id", ondelete="SET NULL", nullable=True)
    retest_result: Mapped[str | None] = mapped_column(String(24))  # fixed | still_vulnerable | inconclusive
    executed_at: Mapped[datetime | None]


class AIUsage(Base, IdMixin, TenantMixin):
    """Token and cost accounting for the platform's own AI-assisted analysis features."""

    __tablename__ = "ai_usage"

    user_id: Mapped[uuid.UUID | None] = fk("users.id", ondelete="SET NULL", nullable=True, index=False)
    provider: Mapped[str] = mapped_column(String(32))
    model: Mapped[str] = mapped_column(String(120))
    purpose: Mapped[str] = mapped_column(String(48))
    prompt_version: Mapped[str] = mapped_column(String(32))
    entity_type: Mapped[str | None] = mapped_column(String(32))
    entity_id: Mapped[uuid.UUID | None]
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd_micros: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(index=True)
