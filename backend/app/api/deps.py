"""Request dependencies: authentication, tenant-scoped DB session, authorization, pagination."""

import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import timedelta
from typing import Annotated, Generic, TypeVar

from fastapi import Depends, Query, Request
from pydantic import BaseModel
from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import Forbidden, Unauthorized
from app.core.security import constant_time_equal, hash_token
from app.db.base import utcnow
from app.db.session import system_session, tenant_session
from app.domains.audit import service as audit
from app.models import User, UserSession

T = TypeVar("T")
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


@dataclass
class Principal:
    user_id: uuid.UUID
    organization_id: uuid.UUID
    email: str
    full_name: str
    role_key: str
    permissions: frozenset[str]
    session_id: uuid.UUID
    mfa_enabled: bool
    mfa_verified: bool

    def has(self, permission: str) -> bool:
        return permission in self.permissions


def _extract_token(request: Request) -> tuple[str | None, bool]:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip(), False
    cookie = request.cookies.get(get_settings().cookie_name)
    return cookie, True


def get_principal(request: Request) -> Principal:
    settings = get_settings()
    token, via_cookie = _extract_token(request)
    if not token:
        raise Unauthorized("Authentication required")
    now = utcnow()
    with system_session() as db:
        session = db.execute(
            select(UserSession).where(UserSession.token_hash == hash_token(token))
        ).scalar_one_or_none()
        if session is None or session.revoked_at is not None or session.expires_at <= now:
            raise Unauthorized("Session is invalid or expired")
        if now - session.last_seen_at > timedelta(minutes=settings.session_idle_minutes):
            session.revoked_at = now
            db.commit()
            raise Unauthorized("Session expired due to inactivity")
        user = db.get(User, session.user_id)
        if user is None or not user.is_active or user.organization_id != session.organization_id:
            raise Unauthorized("Account is disabled")
        from app.models import Organization

        org = db.get(Organization, user.organization_id)
        if org is None or not org.is_active:
            raise Unauthorized("This organization has been suspended")
        # Cookie-authenticated state-changing requests must present the session's CSRF token.
        if via_cookie and request.method not in SAFE_METHODS:
            supplied = request.headers.get("x-csrf-token", "")
            if not supplied or not constant_time_equal(supplied, session.csrf_token):
                raise Forbidden("CSRF token missing or invalid")
        if (settings.require_email_verification and user.email_verified_at is None
                and not request.url.path.startswith("/api/v1/auth/")):
            raise Forbidden("Verify your email address to continue", details={"email_unverified": True})
        if now - session.last_seen_at > timedelta(seconds=60):
            session.last_seen_at = now
        principal = Principal(
            user_id=user.id,
            organization_id=user.organization_id,
            email=user.email,
            full_name=user.full_name,
            role_key=user.role.key,
            permissions=frozenset(user.role.permission_keys),
            session_id=session.id,
            mfa_enabled=user.mfa_enabled,
            mfa_verified=session.mfa_verified,
        )
    request.state.principal = principal
    return principal


def get_verified_principal(principal: Annotated[Principal, Depends(get_principal)]) -> Principal:
    """Principal that has completed MFA when MFA is enabled on the account."""
    if principal.mfa_enabled and not principal.mfa_verified:
        raise Unauthorized("Multi-factor verification required", details={"mfa_required": True})
    return principal


CurrentUser = Annotated[Principal, Depends(get_verified_principal)]


def get_db(principal: CurrentUser) -> Iterator[Session]:
    with tenant_session(principal.organization_id) as session:
        yield session


Db = Annotated[Session, Depends(get_db)]


def require(*permissions: str):
    """Dependency enforcing that the caller holds every listed permission."""

    def checker(principal: CurrentUser) -> Principal:
        missing = [p for p in permissions if p not in principal.permissions]
        if missing:
            with tenant_session(principal.organization_id) as db:
                audit.record(
                    db, organization_id=principal.organization_id, action="authz.denied",
                    actor_user_id=principal.user_id, actor_email=principal.email, outcome="denied",
                    data={"missing": missing},
                )
            raise Forbidden("You do not have permission to perform this action", details={"missing": missing})
        return principal

    return Depends(checker)


def audit_event(db: Session, principal: Principal, action: str, **kwargs) -> None:
    audit.record(
        db, organization_id=principal.organization_id, action=action, actor_user_id=principal.user_id,
        actor_email=principal.email, **kwargs,
    )


class PageParams(BaseModel):
    page: int = 1
    page_size: int = 25

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size


def page_params(page: int = Query(1, ge=1, le=100_000), page_size: int = Query(25, ge=1, le=200)) -> PageParams:
    return PageParams(page=page, page_size=page_size)


Paging = Annotated[PageParams, Depends(page_params)]


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int


def paginate(db: Session, stmt: Select, paging: PageParams, *, scalars: bool = True) -> tuple[list, int]:
    total = db.execute(select(func.count()).select_from(stmt.order_by(None).subquery())).scalar_one()
    result = db.execute(stmt.limit(paging.page_size).offset(paging.offset))
    rows = list(result.scalars().unique()) if scalars else list(result.all())
    return rows, total


def like_escape(term: str) -> str:
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
