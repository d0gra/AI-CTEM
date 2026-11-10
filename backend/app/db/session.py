"""Engine and tenant-scoped sessions.

Tenant isolation is enforced by PostgreSQL row-level security. Every transaction opened by a
session sets two transaction-local settings that the RLS policies read:

  app.current_org  the organization the session acts for (empty when none)
  app.system       'on' for explicitly created system sessions (auth lookups, job claiming)

The settings are applied in `after_begin`, so they are re-established after every commit.
"""

import uuid
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings

_engine: Engine | None = None
_factory: sessionmaker[Session] | None = None


def get_engine() -> Engine:
    global _engine, _factory
    if _engine is None:
        s = get_settings()
        _engine = create_engine(s.database_url, pool_size=s.db_pool_size, max_overflow=10, pool_pre_ping=True)
        _factory = sessionmaker(_engine, expire_on_commit=False, autoflush=False)
    return _engine


def dispose_engine() -> None:
    global _engine, _factory
    if _engine is not None:
        _engine.dispose()
    _engine, _factory = None, None


@event.listens_for(Session, "after_begin")
def _apply_tenant_context(session: Session, _transaction, connection) -> None:
    org_id = session.info.get("org_id")
    connection.execute(
        text("select set_config('app.current_org', :org, true), set_config('app.system', :sys, true)"),
        {"org": str(org_id) if org_id else "", "sys": "on" if session.info.get("system") else "off"},
    )


def _new_session(*, org_id: uuid.UUID | None, system: bool) -> Session:
    get_engine()
    assert _factory is not None
    session = _factory()
    session.info["org_id"] = org_id
    session.info["system"] = system
    return session


@contextmanager
def tenant_session(org_id: uuid.UUID) -> Iterator[Session]:
    """Session restricted by RLS to a single organization."""
    session = _new_session(org_id=org_id, system=False)
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


@contextmanager
def system_session() -> Iterator[Session]:
    """Session that bypasses tenant RLS. Use only for authentication lookups, job dispatch and
    global reference data; never pass request-controlled filters through it without an
    explicit organization predicate."""
    session = _new_session(org_id=None, system=True)
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def org_of(session: Session) -> uuid.UUID:
    org_id = session.info.get("org_id")
    if org_id is None:
        raise RuntimeError("Session has no organization context")
    return org_id
