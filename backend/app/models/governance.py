"""Attack paths, threat intelligence, policies."""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, Float, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, IdMixin, TenantMixin, TimestampMixin, fk


class AttackPath(Base, IdMixin, TenantMixin, TimestampMixin):
    __tablename__ = "attack_paths"
    __table_args__ = (UniqueConstraint("organization_id", "fingerprint"),)

    fingerprint: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(600))
    classification: Mapped[str] = mapped_column(String(16))  # verified | probable | theoretical
    confidence: Mapped[float] = mapped_column(Float)
    score: Mapped[float] = mapped_column(Float, index=True)
    severity: Mapped[str] = mapped_column(String(16))
    involves_ai: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    entry_asset_id: Mapped[uuid.UUID] = fk("assets.id")
    target_asset_id: Mapped[uuid.UUID] = fk("assets.id")
    business_impact: Mapped[str] = mapped_column(Text, default="", server_default="")
    required_conditions: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    remediation_opportunities: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    status: Mapped[str] = mapped_column(String(16), default="active", server_default="active")
    first_seen_at: Mapped[datetime]
    last_computed_at: Mapped[datetime]

    nodes: Mapped[list["AttackPathNode"]] = relationship(
        cascade="all, delete-orphan", order_by="AttackPathNode.position", lazy="selectin"
    )
    edges: Mapped[list["AttackPathEdge"]] = relationship(
        cascade="all, delete-orphan", order_by="AttackPathEdge.position", lazy="selectin"
    )


class AttackPathNode(Base, IdMixin, TenantMixin):
    __tablename__ = "attack_path_nodes"

    attack_path_id: Mapped[uuid.UUID] = fk("attack_paths.id")
    position: Mapped[int] = mapped_column(Integer)
    asset_id: Mapped[uuid.UUID] = fk("assets.id")
    label: Mapped[str] = mapped_column(String(512))
    node_type: Mapped[str] = mapped_column(String(32))
    crosses_trust_boundary: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    finding_ids: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")


class AttackPathEdge(Base, IdMixin, TenantMixin):
    __tablename__ = "attack_path_edges"

    attack_path_id: Mapped[uuid.UUID] = fk("attack_paths.id")
    position: Mapped[int] = mapped_column(Integer)
    relationship_id: Mapped[uuid.UUID | None] = fk("asset_relationships.id", ondelete="SET NULL", nullable=True, index=False)
    relationship_type: Mapped[str] = mapped_column(String(32))
    technique: Mapped[str | None] = mapped_column(String(32))  # ATT&CK / ATLAS technique id
    condition: Mapped[str] = mapped_column(Text, default="", server_default="")
    evidence_level: Mapped[str] = mapped_column(String(16))  # verified | probable | theoretical
    enabling_finding_id: Mapped[uuid.UUID | None] = fk("findings.id", ondelete="SET NULL", nullable=True, index=False)


class ThreatIntelligence(Base, IdMixin, TimestampMixin):
    """Global threat intelligence record with source attribution. Not tenant-owned."""

    __tablename__ = "threat_intelligence"
    __table_args__ = (
        UniqueConstraint("source", "external_id"),
        Index("ix_threat_intel_kind", "kind"),
        Index("ix_threat_intel_title_trgm", "title", postgresql_using="gin", postgresql_ops={"title": "gin_trgm_ops"}),
    )

    source: Mapped[str] = mapped_column(String(32))  # cisa_kev | mitre_attack | mitre_atlas | osv | nvd | ...
    external_id: Mapped[str] = mapped_column(String(120))
    kind: Mapped[str] = mapped_column(String(32))  # exploited_vulnerability | technique | tactic | mitigation | advisory
    title: Mapped[str] = mapped_column(String(600))
    description: Mapped[str] = mapped_column(Text, default="", server_default="")
    confidence: Mapped[str] = mapped_column(String(16), default="high", server_default="high")
    data: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    references: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    source_url: Mapped[str] = mapped_column(String(1000))
    published_at: Mapped[datetime | None]
    source_modified_at: Mapped[datetime | None]
    fetched_at: Mapped[datetime]


class IntelSyncState(Base):
    __tablename__ = "intel_sync_state"

    source: Mapped[str] = mapped_column(String(32), primary_key=True)
    cursor: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    last_success_at: Mapped[datetime | None]
    last_attempt_at: Mapped[datetime | None]
    last_error: Mapped[str | None] = mapped_column(Text)
    records: Mapped[int] = mapped_column(Integer, default=0, server_default="0")


class Policy(Base, IdMixin, TenantMixin, TimestampMixin):
    __tablename__ = "policies"
    __table_args__ = (UniqueConstraint("organization_id", "key"),)

    key: Mapped[str] = mapped_column(String(80))
    name: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="", server_default="")
    severity: Mapped[str] = mapped_column(String(16))
    entity_type: Mapped[str] = mapped_column(String(24))  # asset | finding
    # scope: which entities the policy applies to; condition: what must hold for compliance.
    # Both use the rule grammar documented in app.domains.policy.rules.
    scope: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    condition: Mapped[dict] = mapped_column(JSONB)
    framework_refs: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    last_evaluated_at: Mapped[datetime | None]


class PolicyEvaluation(Base, IdMixin, TenantMixin):
    __tablename__ = "policy_evaluations"
    __table_args__ = (Index("ix_policy_eval_policy_time", "policy_id", "evaluated_at"),)

    policy_id: Mapped[uuid.UUID] = fk("policies.id", index=False)
    evaluated_at: Mapped[datetime]
    total: Mapped[int] = mapped_column(Integer)
    passed: Mapped[int] = mapped_column(Integer)
    failed: Mapped[int] = mapped_column(Integer)
    exempt: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16))  # compliant | non_compliant | not_applicable
    # Violating entities with the field values that caused the failure (capped).
    violations: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")


class PolicyException(Base, IdMixin, TenantMixin, TimestampMixin):
    __tablename__ = "policy_exceptions"

    policy_id: Mapped[uuid.UUID] = fk("policies.id")
    entity_id: Mapped[uuid.UUID]
    reason: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="pending", server_default="pending")
    requested_by_user_id: Mapped[uuid.UUID] = fk("users.id", ondelete="RESTRICT", index=False)
    decided_by_user_id: Mapped[uuid.UUID | None] = fk("users.id", ondelete="SET NULL", nullable=True, index=False)
    decided_at: Mapped[datetime | None]
    expires_at: Mapped[datetime]
