"""Declarative base and column mixins shared by all models."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, MetaData, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

NAMING = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING)
    type_annotation_map = {uuid.UUID: UUID(as_uuid=True), datetime: DateTime(timezone=True)}


class IdMixin:
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), default=utcnow, onupdate=utcnow)


class TenantMixin:
    """Marks a table as tenant-owned. Row-level security is enabled for every such table."""

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )


def fk(target: str, *, ondelete: str = "CASCADE", nullable: bool = False, index: bool = True, **kw):
    return mapped_column(ForeignKey(target, ondelete=ondelete), nullable=nullable, index=index, **kw)


def tenant_tables() -> list[str]:
    return sorted(t.name for t in Base.metadata.tables.values() if "organization_id" in t.c)
