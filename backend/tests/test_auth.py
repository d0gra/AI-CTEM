import uuid

import pyotp
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.security import hash_token
from app.db.session import system_session
from app.models import UserToken
from tests.conftest import PASSWORD, login


def test_register_login_me(org):
    me = org.ok("GET", "/auth/me")
    assert me["role"] == "org_admin" and "assets:read" in me["permissions"]
    assert "platform:admin" not in me["permissions"]


def test_weak_password_rejected(anon):
    r = anon.post("/api/v1/auth/register", json={
        "organization_name": "Weak", "full_name": "x", "email": f"w{uuid.uuid4().hex[:6]}@example.com",
        "password": "aaaaaaaaaaaa",
    })
    assert r.status_code == 422


def test_login_failure_is_generic_and_unauthenticated_denied(anon, org):
    bad = anon.post("/api/v1/auth/login", json={"email": org.email, "password": "wrong-password-123"})
    missing = anon.post("/api/v1/auth/login", json={"email": "nobody@example.com", "password": "wrong-password-123"})
    assert bad.status_code == missing.status_code == 401
    assert bad.json()["error"]["message"] == missing.json()["error"]["message"]
    assert anon.get("/api/v1/assets").status_code == 401
    assert anon.get("/api/v1/auth/me", headers={"Authorization": "Bearer forged"}).status_code == 401


def test_account_lockout(app, org, monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "max_failed_logins", 3)
    http = TestClient(app)
    for _ in range(3):
        assert http.post("/api/v1/auth/login", json={"email": org.email, "password": "x" * 14}).status_code == 401
    r = http.post("/api/v1/auth/login", json={"email": org.email, "password": PASSWORD})
    assert r.status_code == 401 and "locked" in r.json()["error"]["message"]


def test_cookie_session_requires_csrf(app, org):
    http = TestClient(app)
    r = http.post("/api/v1/auth/login", json={"email": org.email, "password": PASSWORD})
    csrf = r.json()["csrf_token"]
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie
    assert http.get("/api/v1/auth/me").status_code == 200
    body = {"name": "csrf-team"}
    assert http.post("/api/v1/admin/teams", json=body).status_code == 403
    assert http.post("/api/v1/admin/teams", json=body, headers={"X-CSRF-Token": "wrong"}).status_code == 403
    assert http.post("/api/v1/admin/teams", json=body, headers={"X-CSRF-Token": csrf}).status_code == 201


def test_logout_and_session_revocation(app, org):
    second = login(app, org.email)
    sessions = org.ok("GET", "/auth/sessions")
    assert len(sessions) == 2
    other = next(s for s in sessions if not s["current"])
    org.ok("DELETE", f"/auth/sessions/{other['id']}", expected=204)
    assert second.get("/auth/me").status_code == 401
    org.ok("POST", "/auth/logout", expected=204)
    assert org.get("/auth/me").status_code == 401


def test_mfa_enrolment_and_enforcement(app, org):
    setup = org.ok("POST", "/auth/mfa/setup")
    totp = pyotp.TOTP(setup["secret"])
    assert org.post("/auth/mfa/enable", json={"code": "000000"}).status_code == 422
    org.ok("POST", "/auth/mfa/enable", json={"code": totp.now()}, expected=204)
    http = TestClient(app)
    r = http.post("/api/v1/auth/login", json={"email": org.email, "password": PASSWORD})
    assert r.json()["mfa_required"] is True
    bearer = {"Authorization": f"Bearer {r.json()['access_token']}"}
    blocked = http.get("/api/v1/admin/roles", headers=bearer)
    assert blocked.status_code == 401 and blocked.json()["error"]["details"]["mfa_required"] is True
    assert http.post("/api/v1/auth/mfa/verify", json={"code": "123456"}, headers=bearer).status_code == 401
    assert http.post("/api/v1/auth/mfa/verify", json={"code": totp.now()}, headers=bearer).status_code == 204
    assert http.get("/api/v1/admin/roles", headers=bearer).status_code == 200


def _inject_token(email: str, purpose: str) -> str:
    """Replace the emailed token with a known value (the raw token is never stored)."""
    from app.models import User

    raw = uuid.uuid4().hex + uuid.uuid4().hex
    with system_session() as db:
        user = db.execute(select(User).where(User.email == email)).scalar_one()
        token = db.execute(
            select(UserToken).where(UserToken.user_id == user.id, UserToken.purpose == purpose,
                                    UserToken.used_at.is_(None))
        ).scalar_one()
        token.token_hash = hash_token(raw)
    return raw


def test_password_reset_flow_revokes_sessions_and_is_single_use(anon, app, org):
    assert anon.post("/api/v1/auth/password/forgot", json={"email": "ghost@example.com"}).status_code == 202
    assert anon.post("/api/v1/auth/password/forgot", json={"email": org.email}).status_code == 202
    raw = _inject_token(org.email, "password_reset")
    new_password = "A-Different-Passphrase-77"
    assert anon.post("/api/v1/auth/password/reset", json={"token": raw, "new_password": new_password}).status_code == 204
    assert org.get("/auth/me").status_code == 401  # prior sessions revoked
    assert anon.post("/api/v1/auth/password/reset", json={"token": raw, "new_password": new_password}).status_code == 422
    assert login(app, org.email, new_password).get("/auth/me").status_code == 200


def test_email_verification(anon, org):
    raw = _inject_token(org.email, "verify_email")
    assert anon.post("/api/v1/auth/email/verify", json={"token": raw}).status_code == 204
    assert anon.post("/api/v1/auth/email/verify", json={"token": raw}).status_code == 422


def test_security_headers_and_health(anon):
    r = anon.get("/healthz")
    assert r.status_code == 200
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    ready = anon.get("/readyz")
    assert ready.status_code == 200 and ready.json()["checks"]["database"] == "ok"
    assert "ctem_http_requests_total" in anon.get("/metrics").text


def test_rate_limit_on_auth_endpoints(app, monkeypatch):
    from app.core import ratelimit
    from app.core.config import get_settings

    ratelimit.reset_local()
    monkeypatch.setattr(get_settings(), "rate_limit_auth", 3)
    http = TestClient(app)
    codes = [
        http.post("/api/v1/auth/login", json={"email": "rl@example.com", "password": "x" * 14}).status_code
        for _ in range(5)
    ]
    ratelimit.reset_local()
    assert codes[:3] == [401, 401, 401] and codes[3:] == [429, 429]
