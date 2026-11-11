"""Authentication: registration, login, sessions, MFA, password reset, email verification."""

import re
import uuid
from datetime import timedelta

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.context import get_request_context
from app.core.email import send_account_email
from app.core.errors import Conflict, Forbidden, Unauthorized, ValidationFailed
from app.core.permissions import BUILTIN_ROLES
from app.core.security import (
    DUMMY_HASH,
    decrypt_secret,
    encrypt_secret,
    hash_password,
    hash_token,
    new_token,
    new_totp_secret,
    password_needs_rehash,
    totp_uri,
    verify_password,
    verify_totp,
)
from app.db.base import utcnow
from app.db.session import system_session
from app.domains.audit import service as audit
from app.models import Organization, Role, RolePermission, User, UserSession, UserToken

RESET_TTL = timedelta(hours=1)
VERIFY_TTL = timedelta(days=3)


def validate_password(password: str, email: str) -> None:
    problems = []
    if len(password) < 12:
        problems.append("must be at least 12 characters")
    if len(password) > 256:
        problems.append("must be at most 256 characters")
    if email and email.split("@")[0].lower() in password.lower() and len(email.split("@")[0]) >= 4:
        problems.append("must not contain your email name")
    if len(set(password)) < 5:
        problems.append("must not be a trivially repeated pattern")
    if problems:
        raise ValidationFailed("Password " + "; ".join(problems))


def _slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:60] or "org"
    return f"{slug}-{uuid.uuid4().hex[:6]}"


def create_builtin_roles(db: Session, organization_id: uuid.UUID) -> dict[str, Role]:
    roles = {}
    for key, (name, permissions) in BUILTIN_ROLES.items():
        if key == "super_admin":
            continue  # granted only through the platform bootstrap CLI
        role = Role(organization_id=organization_id, key=key, name=name, is_builtin=True)
        role.permissions = [
            RolePermission(organization_id=organization_id, permission_key=p) for p in sorted(permissions)
        ]
        db.add(role)
        roles[key] = role
    db.flush()
    return roles


def register_organization(*, organization_name: str, email: str, full_name: str, password: str) -> User:
    settings = get_settings()
    if not settings.allow_registration:
        raise Forbidden("Self-service registration is disabled")
    email = email.lower().strip()
    validate_password(password, email)
    with system_session() as db:
        if db.execute(select(User.id).where(User.email == email)).first():
            # Do not reveal which addresses are registered beyond a generic conflict.
            raise Conflict("Registration could not be completed with these details")
        org = Organization(name=organization_name.strip(), slug=_slugify(organization_name))
        db.add(org)
        db.flush()
        roles = create_builtin_roles(db, org.id)
        user = User(
            organization_id=org.id, email=email, full_name=full_name.strip(),
            password_hash=hash_password(password), role_id=roles["org_admin"].id,
        )
        db.add(user)
        try:
            db.flush()
        except IntegrityError as exc:
            raise Conflict("Registration could not be completed with these details") from exc
        from app.domains.policy.service import install_default_policies

        install_default_policies(db, org.id)
        audit.record(db, organization_id=org.id, action="organization.registered", actor_user_id=user.id,
                     actor_email=email, entity_type="organization", entity_id=org.id)
        issue_email_verification(db, user)
        db.refresh(user)
        return user


def _issue_token(db: Session, user: User, purpose: str, ttl: timedelta) -> str:
    db.execute(
        update(UserToken)
        .where(UserToken.user_id == user.id, UserToken.purpose == purpose, UserToken.used_at.is_(None))
        .values(used_at=utcnow())
    )
    token = new_token()
    db.add(UserToken(
        organization_id=user.organization_id, user_id=user.id, purpose=purpose, token_hash=hash_token(token),
        created_at=utcnow(), expires_at=utcnow() + ttl,
    ))
    return token


def issue_email_verification(db: Session, user: User) -> None:
    token = _issue_token(db, user, "verify_email", VERIFY_TTL)
    link = f"{get_settings().public_base_url}/verify-email?token={token}"
    send_account_email(user.email, "Verify your email address",
                       f"Confirm your email address for the CTEM platform:\n\n{link}\n", dev_link=link)


def _consume_token(db: Session, token: str, purpose: str) -> User:
    row = db.execute(
        select(UserToken).where(UserToken.token_hash == hash_token(token), UserToken.purpose == purpose)
        .with_for_update()
    ).scalar_one_or_none()
    if row is None or row.used_at is not None or row.expires_at <= utcnow():
        raise ValidationFailed("This link is invalid or has expired")
    row.used_at = utcnow()
    user = db.get(User, row.user_id)
    if user is None or not user.is_active:
        raise ValidationFailed("This link is invalid or has expired")
    return user


def verify_email(token: str) -> None:
    with system_session() as db:
        user = _consume_token(db, token, "verify_email")
        user.email_verified_at = utcnow()
        audit.record(db, organization_id=user.organization_id, action="auth.email_verified",
                     actor_user_id=user.id, actor_email=user.email)


def request_password_reset(email: str) -> None:
    """Always succeeds from the caller's perspective to avoid account enumeration."""
    with system_session() as db:
        user = db.execute(select(User).where(User.email == email.lower().strip())).scalar_one_or_none()
        if user is None or not user.is_active:
            return
        token = _issue_token(db, user, "password_reset", RESET_TTL)
        link = f"{get_settings().public_base_url}/reset-password?token={token}"
        send_account_email(user.email, "Reset your password",
                           f"A password reset was requested for your account. This link is valid for one hour:\n\n{link}\n\n"
                           "If you did not request this, you can ignore this message.", dev_link=link)
        audit.record(db, organization_id=user.organization_id, action="auth.password_reset_requested",
                     actor_user_id=user.id, actor_email=user.email)


def reset_password(token: str, new_password: str) -> None:
    with system_session() as db:
        user = _consume_token(db, token, "password_reset")
        validate_password(new_password, user.email)
        user.password_hash = hash_password(new_password)
        user.failed_login_count, user.locked_until = 0, None
        revoke_all_sessions(db, user.id)
        audit.record(db, organization_id=user.organization_id, action="auth.password_reset",
                     actor_user_id=user.id, actor_email=user.email)


def revoke_all_sessions(db: Session, user_id: uuid.UUID, *, except_session: uuid.UUID | None = None) -> None:
    stmt = update(UserSession).where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
    if except_session:
        stmt = stmt.where(UserSession.id != except_session)
    db.execute(stmt.values(revoked_at=utcnow()))


def login(email: str, password: str, totp_code: str | None) -> tuple[User, UserSession, str]:
    """Authenticate and create a session. Returns (user, session, raw session token)."""
    settings = get_settings()
    ctx = get_request_context()
    email = email.lower().strip()
    now = utcnow()
    with system_session() as db:
        user = db.execute(select(User).where(User.email == email).with_for_update(of=User)).scalar_one_or_none()
        if user is None:
            verify_password(password, DUMMY_HASH)  # equalise timing
            raise Unauthorized("Invalid email or password")
        if user.locked_until and user.locked_until > now:
            audit.record(db, organization_id=user.organization_id, action="auth.login", actor_user_id=user.id,
                         actor_email=email, outcome="denied", data={"reason": "locked"})
            db.commit()
            raise Unauthorized("Account temporarily locked due to repeated failed sign-in attempts")
        if not verify_password(password, user.password_hash) or not user.is_active:
            user.failed_login_count += 1
            if user.failed_login_count >= settings.max_failed_logins:
                user.locked_until = now + timedelta(minutes=settings.lockout_minutes)
                user.failed_login_count = 0
            audit.record(db, organization_id=user.organization_id, action="auth.login", actor_user_id=user.id,
                         actor_email=email, outcome="failure", data={"reason": "bad_credentials"})
            db.commit()
            raise Unauthorized("Invalid email or password")
        org = db.get(Organization, user.organization_id)
        if org is None or not org.is_active:
            raise Unauthorized("Invalid email or password")
        mfa_verified = False
        if user.mfa_enabled and totp_code:
            if not verify_totp(decrypt_secret(user.mfa_secret_encrypted or ""), totp_code):
                user.failed_login_count += 1
                audit.record(db, organization_id=user.organization_id, action="auth.login",
                             actor_user_id=user.id, actor_email=email, outcome="failure",
                             data={"reason": "bad_totp"})
                db.commit()
                raise Unauthorized("Invalid verification code")
            mfa_verified = True
        if password_needs_rehash(user.password_hash):
            user.password_hash = hash_password(password)
        user.failed_login_count, user.locked_until, user.last_login_at = 0, None, now
        token = new_token()
        session = UserSession(
            organization_id=user.organization_id, user_id=user.id, token_hash=hash_token(token),
            csrf_token=new_token(24), mfa_verified=mfa_verified, created_at=now, last_seen_at=now,
            expires_at=now + timedelta(minutes=settings.session_ttl_minutes),
            ip_address=ctx.ip_address, user_agent=(ctx.user_agent or "")[:400] or None,
        )
        db.add(session)
        audit.record(db, organization_id=user.organization_id, action="auth.login", actor_user_id=user.id,
                     actor_email=email, data={"mfa": user.mfa_enabled, "mfa_verified": mfa_verified})
        db.flush()
        return user, session, token


def verify_session_mfa(session_id: uuid.UUID, user_id: uuid.UUID, code: str) -> None:
    with system_session() as db:
        user = db.get(User, user_id)
        session = db.get(UserSession, session_id)
        if not user or not session or not user.mfa_enabled or not user.mfa_secret_encrypted:
            raise Unauthorized("Multi-factor authentication is not enabled")
        if not verify_totp(decrypt_secret(user.mfa_secret_encrypted), code):
            audit.record(db, organization_id=user.organization_id, action="auth.mfa_verify",
                         actor_user_id=user.id, actor_email=user.email, outcome="failure")
            db.commit()
            raise Unauthorized("Invalid verification code")
        session.mfa_verified = True
        audit.record(db, organization_id=user.organization_id, action="auth.mfa_verify",
                     actor_user_id=user.id, actor_email=user.email)


def begin_mfa_setup(db: Session, user_id: uuid.UUID) -> tuple[str, str]:
    user = db.get(User, user_id)
    assert user is not None
    if user.mfa_enabled:
        raise Conflict("Multi-factor authentication is already enabled")
    secret = new_totp_secret()
    user.mfa_secret_encrypted = encrypt_secret(secret)
    return secret, totp_uri(secret, user.email)


def enable_mfa(db: Session, user_id: uuid.UUID, session_id: uuid.UUID, code: str) -> None:
    user = db.get(User, user_id)
    assert user is not None
    if user.mfa_enabled or not user.mfa_secret_encrypted:
        raise Conflict("Start MFA setup first")
    if not verify_totp(decrypt_secret(user.mfa_secret_encrypted), code):
        raise ValidationFailed("Invalid verification code")
    user.mfa_enabled = True
    session = db.get(UserSession, session_id)
    if session:
        session.mfa_verified = True
    revoke_all_sessions(db, user.id, except_session=session_id)


def disable_mfa(db: Session, user_id: uuid.UUID, password: str, code: str) -> None:
    user = db.get(User, user_id)
    assert user is not None
    if not user.mfa_enabled or not user.mfa_secret_encrypted:
        raise Conflict("Multi-factor authentication is not enabled")
    if not verify_password(password, user.password_hash) or not verify_totp(
        decrypt_secret(user.mfa_secret_encrypted), code
    ):
        raise Unauthorized("Password or verification code is incorrect")
    user.mfa_enabled, user.mfa_secret_encrypted = False, None


def change_password(db: Session, user_id: uuid.UUID, session_id: uuid.UUID, current: str, new: str) -> None:
    user = db.get(User, user_id)
    assert user is not None
    if not verify_password(current, user.password_hash):
        raise Unauthorized("Current password is incorrect")
    validate_password(new, user.email)
    user.password_hash = hash_password(new)
    revoke_all_sessions(db, user.id, except_session=session_id)
