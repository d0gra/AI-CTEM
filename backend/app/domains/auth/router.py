import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select

from app.api.deps import CurrentUser, Db, Principal, audit_event, get_principal
from app.core.config import get_settings
from app.core.errors import NotFound
from app.db.base import utcnow
from app.domains.auth import service
from app.models import UserSession

router = APIRouter(prefix="/auth", tags=["Authentication"])


class RegisterIn(BaseModel):
    organization_name: str = Field(min_length=2, max_length=200)
    full_name: str = Field(min_length=1, max_length=200)
    email: EmailStr
    password: str = Field(min_length=12, max_length=256)


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(max_length=256)
    totp_code: str | None = Field(default=None, max_length=12)


class UserOut(BaseModel):
    email_verified: bool = False
    email_verification_required: bool = False
    id: uuid.UUID
    organization_id: uuid.UUID
    email: str
    full_name: str
    role: str
    permissions: list[str]
    mfa_enabled: bool
    mfa_verified: bool


class LoginOut(BaseModel):
    mfa_required: bool
    csrf_token: str
    # Returned so non-browser API clients can use `Authorization: Bearer`. Browsers rely on the
    # HttpOnly cookie and should discard this value.
    access_token: str
    expires_at: datetime


class SessionOut(BaseModel):
    id: uuid.UUID
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    ip_address: str | None
    user_agent: str | None
    current: bool


class CodeIn(BaseModel):
    code: str = Field(min_length=6, max_length=12)


class TokenIn(BaseModel):
    token: str = Field(min_length=10, max_length=200)


class ResetIn(TokenIn):
    new_password: str = Field(min_length=12, max_length=256)


class EmailIn(BaseModel):
    email: EmailStr


class PasswordChangeIn(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


class MfaDisableIn(BaseModel):
    password: str = Field(max_length=256)
    code: str = Field(min_length=6, max_length=12)


def _set_cookie(response: Response, token: str, expires_at: datetime) -> None:
    s = get_settings()
    response.set_cookie(
        s.cookie_name, token, httponly=True, secure=s.cookie_secure, samesite="lax", path="/",
        max_age=int((expires_at - utcnow()).total_seconds()),
    )


@router.post("/register", status_code=201)
def register(body: RegisterIn) -> dict:
    user = service.register_organization(
        organization_name=body.organization_name, email=body.email, full_name=body.full_name,
        password=body.password,
    )
    return {"organization_id": user.organization_id, "user_id": user.id}


@router.post("/login", response_model=LoginOut)
def login(body: LoginIn, response: Response) -> LoginOut:
    user, session, token = service.login(body.email, body.password, body.totp_code)
    _set_cookie(response, token, session.expires_at)
    return LoginOut(
        mfa_required=user.mfa_enabled and not session.mfa_verified, csrf_token=session.csrf_token,
        access_token=token, expires_at=session.expires_at,
    )


@router.post("/mfa/verify", status_code=204)
def mfa_verify(body: CodeIn, principal: Principal = Depends(get_principal)) -> None:
    service.verify_session_mfa(principal.session_id, principal.user_id, body.code)


@router.post("/logout", status_code=204)
def logout(response: Response, db: Db, principal: CurrentUser) -> None:
    session = db.get(UserSession, principal.session_id)
    if session:
        session.revoked_at = utcnow()
    audit_event(db, principal, "auth.logout")
    response.delete_cookie(get_settings().cookie_name, path="/")


@router.get("/me", response_model=UserOut)
def me(principal: Principal = Depends(get_principal)) -> UserOut:
    from app.db.session import system_session
    from app.models import User

    with system_session() as db:
        user = db.get(User, principal.user_id)
        verified = bool(user and user.email_verified_at)
    return UserOut(
        email_verified=verified, email_verification_required=get_settings().require_email_verification,
        id=principal.user_id, organization_id=principal.organization_id, email=principal.email,
        full_name=principal.full_name, role=principal.role_key, permissions=sorted(principal.permissions),
        mfa_enabled=principal.mfa_enabled, mfa_verified=principal.mfa_verified,
    )


@router.get("/csrf")
def csrf(db: Db, principal: CurrentUser) -> dict:
    session = db.get(UserSession, principal.session_id)
    return {"csrf_token": session.csrf_token if session else ""}


@router.get("/sessions", response_model=list[SessionOut])
def list_sessions(db: Db, principal: CurrentUser) -> list[SessionOut]:
    rows = db.execute(
        select(UserSession)
        .where(UserSession.user_id == principal.user_id, UserSession.revoked_at.is_(None),
               UserSession.expires_at > utcnow())
        .order_by(UserSession.last_seen_at.desc())
    ).scalars()
    return [
        SessionOut(id=s.id, created_at=s.created_at, last_seen_at=s.last_seen_at, expires_at=s.expires_at,
                   ip_address=s.ip_address, user_agent=s.user_agent, current=s.id == principal.session_id)
        for s in rows
    ]


@router.delete("/sessions/{session_id}", status_code=204)
def revoke_session(session_id: uuid.UUID, db: Db, principal: CurrentUser) -> None:
    session = db.get(UserSession, session_id)
    if session is None or session.user_id != principal.user_id:
        raise NotFound("Session not found")
    session.revoked_at = utcnow()
    audit_event(db, principal, "auth.session_revoked", entity_type="session", entity_id=session_id)


@router.post("/mfa/setup")
def mfa_setup(db: Db, principal: CurrentUser) -> dict:
    secret, uri = service.begin_mfa_setup(db, principal.user_id)
    return {"secret": secret, "otpauth_uri": uri}


@router.post("/mfa/enable", status_code=204)
def mfa_enable(body: CodeIn, db: Db, principal: CurrentUser) -> None:
    service.enable_mfa(db, principal.user_id, principal.session_id, body.code)
    audit_event(db, principal, "auth.mfa_enabled")


@router.post("/mfa/disable", status_code=204)
def mfa_disable(body: MfaDisableIn, db: Db, principal: CurrentUser) -> None:
    service.disable_mfa(db, principal.user_id, body.password, body.code)
    audit_event(db, principal, "auth.mfa_disabled")


@router.post("/password/change", status_code=204)
def password_change(body: PasswordChangeIn, db: Db, principal: CurrentUser) -> None:
    service.change_password(db, principal.user_id, principal.session_id, body.current_password, body.new_password)
    audit_event(db, principal, "auth.password_changed")


@router.post("/password/forgot", status_code=202)
def password_forgot(body: EmailIn) -> dict:
    service.request_password_reset(body.email)
    return {"detail": "If the account exists, a reset link has been sent."}


@router.post("/password/reset", status_code=204)
def password_reset(body: ResetIn) -> None:
    service.reset_password(body.token, body.new_password)


@router.post("/email/resend", status_code=202)
def email_resend(principal: Principal = Depends(get_principal)) -> dict:
    from app.db.session import tenant_session
    from app.models import User

    with tenant_session(principal.organization_id) as db:
        user = db.get(User, principal.user_id)
        if user is not None and user.email_verified_at is None:
            service.issue_email_verification(db, user)
    return {"detail": "If your address is not yet verified, a new link has been sent."}


@router.post("/email/verify", status_code=204)
def email_verify(body: TokenIn) -> None:
    service.verify_email(body.token)
