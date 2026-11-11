"""Integrations, notifications, reports and the audit log."""

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, Boolean, Identity, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, IdMixin, TenantMixin, TimestampMixin, fk


class Integration(Base, IdMixin, TenantMixin, TimestampMixin):
    __tablename__ = "integrations"
    __table_args__ = (UniqueConstraint("organization_id", "name"),)

    connector: Mapped[str] = mapped_column(String(48))  # key in the connector registry
    name: Mapped[str] = mapped_column(String(200))
    config: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")  # non-secret settings
    credentials_encrypted: Mapped[str | None] = mapped_column(Text)  # Fernet token of a JSON object
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    health: Mapped[str] = mapped_column(String(16), default="unverified", server_default="unverified")
    last_checked_at: Mapped[datetime | None]
    last_error: Mapped[str | None] = mapped_column(Text)
    last_error_class: Mapped[str | None] = mapped_column(String(24))
    last_sync_at: Mapped[datetime | None]  # last successful assessment that used this integration


class Notification(Base, IdMixin, TenantMixin):
    __tablename__ = "notifications"
    __table_args__ = (
        # Storm control: one notification per dedup key (event type + entity + time bucket).
        UniqueConstraint("organization_id", "dedup_key"),
        Index("ix_notifications_org_time", "organization_id", "created_at"),
    )

    event_type: Mapped[str] = mapped_column(String(48))
    severity: Mapped[str] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(String(400))
    body: Mapped[str] = mapped_column(Text, default="", server_default="")
    entity_type: Mapped[str | None] = mapped_column(String(32))
    entity_id: Mapped[uuid.UUID | None]
    dedup_key: Mapped[str] = mapped_column(String(200))
    occurrences: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    created_at: Mapped[datetime]


class NotificationRead(Base, TenantMixin):
    __tablename__ = "notification_reads"

    notification_id: Mapped[uuid.UUID] = fk("notifications.id", primary_key=True, index=False)
    user_id: Mapped[uuid.UUID] = fk("users.id", primary_key=True, index=False)
    read_at: Mapped[datetime]


class NotificationRule(Base, IdMixin, TenantMixin, TimestampMixin):
    __tablename__ = "notification_rules"

    name: Mapped[str] = mapped_column(String(200))
    event_types: Mapped[list[str]] = mapped_column(ARRAY(String(48)), default=list, server_default="{}")
    min_severity: Mapped[str] = mapped_column(String(16), default="high", server_default="high")
    channel: Mapped[str] = mapped_column(String(16))  # email | webhook | slack | teams
    integration_id: Mapped[uuid.UUID | None] = fk("integrations.id", ondelete="CASCADE", nullable=True)
    email_to: Mapped[str | None] = mapped_column(String(320))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")


class NotificationDelivery(Base, IdMixin, TenantMixin):
    __tablename__ = "notification_deliveries"
    __table_args__ = (UniqueConstraint("notification_id", "rule_id"),)

    notification_id: Mapped[uuid.UUID] = fk("notifications.id")
    rule_id: Mapped[uuid.UUID] = fk("notification_rules.id")
    status: Mapped[str] = mapped_column(String(16))  # sent | failed
    error: Mapped[str | None] = mapped_column(Text)
    attempted_at: Mapped[datetime]


class Report(Base, IdMixin, TenantMixin, TimestampMixin):
    __tablename__ = "reports"

    type: Mapped[str] = mapped_column(String(32))
    format: Mapped[str] = mapped_column(String(8))
    title: Mapped[str] = mapped_column(String(300))
    params: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    status: Mapped[str] = mapped_column(String(16), default="queued", server_default="queued")
    error: Mapped[str | None] = mapped_column(Text)
    job_id: Mapped[uuid.UUID | None] = fk("jobs.id", ondelete="SET NULL", nullable=True, index=False)
    storage_key: Mapped[str | None] = mapped_column(String(300))
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    sha256: Mapped[str | None] = mapped_column(String(64))
    generated_at: Mapped[datetime | None]
    requested_by_user_id: Mapped[uuid.UUID | None] = fk("users.id", ondelete="SET NULL", nullable=True, index=False)


class AuditEvent(Base, TenantMixin):
    """Append-only, hash-chained audit record. The application role has INSERT/SELECT only."""

    __tablename__ = "audit_events"
    __table_args__ = (Index("ix_audit_org_seq", "organization_id", "seq"),)

    seq: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    occurred_at: Mapped[datetime]
    actor_user_id: Mapped[uuid.UUID | None]
    actor_email: Mapped[str | None] = mapped_column(String(320))
    action: Mapped[str] = mapped_column(String(80), index=True)
    entity_type: Mapped[str | None] = mapped_column(String(48))
    entity_id: Mapped[str | None] = mapped_column(String(64))
    outcome: Mapped[str] = mapped_column(String(16), default="success", server_default="success")
    ip_address: Mapped[str | None] = mapped_column(String(64))
    request_id: Mapped[str | None] = mapped_column(String(64))
    data: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))
