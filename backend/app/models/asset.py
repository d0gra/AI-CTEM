"""Unified asset inventory, relationships (the asset graph), discovery provenance and scope."""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, Float, Index, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, IdMixin, TenantMixin, TimestampMixin, fk

ASSET_TYPES = (
    "domain", "subdomain", "ip_address", "dns_record", "website", "http_service", "api", "api_endpoint",
    "certificate", "cloud_account", "cloud_resource", "load_balancer", "storage", "database",
    "network_service", "host", "container_image", "k8s_resource", "repository", "package", "identity",
    "ai_application", "llm_endpoint", "ai_agent", "mcp_server", "mcp_client", "ai_model",
    "vector_database", "rag_application", "ai_framework", "ai_provider", "model_registry", "data_source",
)
AI_ASSET_TYPES = (
    "ai_application", "llm_endpoint", "ai_agent", "mcp_server", "mcp_client", "ai_model",
    "vector_database", "rag_application", "ai_framework", "ai_provider", "model_registry",
)
RELATIONSHIP_TYPES = (
    "CONNECTS_TO", "RUNS_ON", "EXPOSES", "AUTHENTICATES_TO", "HAS_PERMISSION", "DEPENDS_ON", "TRUSTS",
    "CONTAINS", "RETRIEVES_FROM", "INVOKES_TOOL", "PROCESSES_DATA", "AFFECTED_BY", "RESOLVES_TO",
    "SECURED_BY", "CAN_ASSUME",
)
ENVIRONMENTS = ("production", "staging", "development", "test", "unknown")
CRITICALITIES = ("critical", "high", "medium", "low")
EXPOSURES = ("internet", "internal", "private", "unknown")
SENSITIVITIES = ("restricted", "confidential", "internal", "public", "unknown")


class Asset(Base, IdMixin, TenantMixin, TimestampMixin):
    __tablename__ = "assets"
    __table_args__ = (
        # Identity is the canonical, type-qualified identifier (e.g. an ARN or FQDN), never the
        # display name: two assets with the same name are not assumed to be the same asset.
        UniqueConstraint("organization_id", "type", "identifier"),
        Index("ix_assets_org_type", "organization_id", "type"),
        Index("ix_assets_org_exposure", "organization_id", "exposure"),
        Index("ix_assets_identifier_trgm", "identifier", postgresql_using="gin",
              postgresql_ops={"identifier": "gin_trgm_ops"}),
        Index("ix_assets_name_trgm", "name", postgresql_using="gin", postgresql_ops={"name": "gin_trgm_ops"}),
    )

    type: Mapped[str] = mapped_column(String(32))
    identifier: Mapped[str] = mapped_column(String(1024))
    name: Mapped[str] = mapped_column(String(512))
    description: Mapped[str] = mapped_column(Text, default="", server_default="")
    environment: Mapped[str] = mapped_column(String(16), default="unknown", server_default="unknown")
    criticality: Mapped[str] = mapped_column(String(16), default="medium", server_default="medium")
    exposure: Mapped[str] = mapped_column(String(16), default="unknown", server_default="unknown")
    data_sensitivity: Mapped[str] = mapped_column(String(16), default="unknown", server_default="unknown")
    business_unit: Mapped[str | None] = mapped_column(String(120))
    owner_user_id: Mapped[uuid.UUID | None] = fk("users.id", ondelete="SET NULL", nullable=True)
    owner_team_id: Mapped[uuid.UUID | None] = fk("teams.id", ondelete="SET NULL", nullable=True)
    tags: Mapped[list[str]] = mapped_column(ARRAY(String(64)), default=list, server_default="{}")
    # Provider- or protocol-specific metadata (HTTP headers, cloud attributes, fingerprints).
    attributes: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    discovery_sources: Mapped[list[str]] = mapped_column(ARRAY(String(64)), default=list, server_default="{}")
    status: Mapped[str] = mapped_column(String(16), default="active", server_default="active")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, server_default="0")
    first_seen_at: Mapped[datetime]
    last_seen_at: Mapped[datetime]


class AssetRelationship(Base, IdMixin, TenantMixin, TimestampMixin):
    __tablename__ = "asset_relationships"
    __table_args__ = (UniqueConstraint("organization_id", "source_asset_id", "target_asset_id", "type"),)

    source_asset_id: Mapped[uuid.UUID] = fk("assets.id")
    target_asset_id: Mapped[uuid.UUID] = fk("assets.id")
    type: Mapped[str] = mapped_column(String(32))
    source: Mapped[str] = mapped_column(String(64))  # provenance: which discovery produced the edge
    confidence: Mapped[float] = mapped_column(Float, default=1.0, server_default="1")
    evidence: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    first_seen_at: Mapped[datetime]
    last_seen_at: Mapped[datetime]


class AssetDiscoveryEvent(Base, IdMixin, TenantMixin):
    """Append-only asset history: first discovery, re-observation, attribute changes."""

    __tablename__ = "asset_discovery_events"
    __table_args__ = (Index("ix_asset_events_asset_time", "asset_id", "occurred_at"),)

    asset_id: Mapped[uuid.UUID] = fk("assets.id", index=False)
    event_type: Mapped[str] = mapped_column(String(24))  # discovered | observed | changed | stale | manual
    source: Mapped[str] = mapped_column(String(64))
    job_id: Mapped[uuid.UUID | None] = fk("jobs.id", ondelete="SET NULL", nullable=True)
    actor_user_id: Mapped[uuid.UUID | None] = fk("users.id", ondelete="SET NULL", nullable=True, index=False)
    details: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    occurred_at: Mapped[datetime]


class ScopeTarget(Base, IdMixin, TenantMixin, TimestampMixin):
    """An explicitly authorized assessment target. Active checks refuse anything not covered."""

    __tablename__ = "scope_targets"
    __table_args__ = (UniqueConstraint("organization_id", "kind", "value"),)

    kind: Mapped[str] = mapped_column(String(16))  # domain | cidr | url | path
    value: Mapped[str] = mapped_column(String(1024))
    allow_active: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    allow_private_network: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    authorization_note: Mapped[str] = mapped_column(Text)
    authorized_by_user_id: Mapped[uuid.UUID | None] = fk("users.id", ondelete="SET NULL", nullable=True)
    expires_at: Mapped[datetime | None]
