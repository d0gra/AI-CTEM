"""Public demo mode: seeded accounts per role, and the guards that keep a shared instance usable and safe."""

import httpx
import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.domains import demo
from app.integrations.intel import sources as intel
from tests.conftest import login
from tests.test_scanners import osv_transport


@pytest.fixture
def demo_on(monkeypatch, tmp_path):
    s = get_settings()
    monkeypatch.setattr(s, "demo_mode", True)
    monkeypatch.setattr(s, "repo_scan_root", str(tmp_path))
    monkeypatch.setattr(intel, "TRANSPORT", httpx.MockTransport(osv_transport))  # no live OSV or feed traffic
    return s


def test_demo_endpoint_absent_unless_enabled(app):
    assert TestClient(app).get("/api/v1/demo").status_code == 404


def test_seed_creates_one_account_per_role_and_sample_analysis(app, demo_on, drain):
    first = demo.seed()
    assert demo.seed()["created"] is False  # idempotent
    info = TestClient(app).get("/api/v1/demo").json()
    assert {a["role"] for a in info["accounts"]} == {key for key, *_ in demo.ACCOUNTS} and len(info["accounts"]) == 9
    for account in info["accounts"]:
        me = login(app, account["email"], info["password"]).get("/auth/me").json()
        assert me["role"] == account["role"] and me["organization_id"] == first["organization_id"]

    drain()
    analyst = login(app, demo.email_for("analyst"), demo_on.demo_password)
    rules = {f["rule_id"] for f in analyst.ok("GET", "/findings", params={"page_size": 200})["items"]}
    assert any(r.startswith("ai.") for r in rules), rules  # findings come from the real repository analysis engine
    assert analyst.ok("GET", "/ai/assets")["total"] > 0


def test_guards_protect_shared_accounts_and_block_active_testing(app, demo_on):
    demo.seed()
    admin = login(app, demo.email_for("org.admin"), demo_on.demo_password)
    assert admin.post("/auth/password/change", json={"current_password": demo_on.demo_password, "new_password": "Another-long-pass-1"}).status_code == 403
    assert admin.post("/auth/mfa/setup").status_code == 403
    viewer = next(u for u in admin.ok("GET", "/admin/users", params={"page_size": 50})["items"] if u["email"] == demo.email_for("viewer"))
    assert admin.patch(f"/admin/users/{viewer['id']}", json={"is_active": False}).status_code == 403

    # Failed sign-ins never lock a demo account.
    http = TestClient(app)
    for _ in range(demo_on.max_failed_logins + 2):
        http.post("/api/v1/auth/login", json={"email": demo.email_for("viewer"), "password": "wrong-password-123"})
    login(app, demo.email_for("viewer"), demo_on.demo_password)

    # Active engines refuse to run; a dry run still explains what would happen.
    admin.ok("POST", "/scope", json={"kind": "url", "value": "https://app.example.com", "allow_active": True,
                                     "authorization_note": "Demo test entry for guard verification"})
    a = admin.ok("POST", "/assessments", json={"name": "Exposure", "kind": "http_exposure", "targets": [{"kind": "url", "value": "https://app.example.com"}]})
    refused = admin.post(f"/assessments/{a['id']}/run", json={"dry_run": False})
    assert refused.status_code == 403 and "public demo" in refused.json()["error"]["message"]
    assert admin.post(f"/assessments/{a['id']}/run", json={"dry_run": True}).status_code in (200, 201, 202)

    # Credentials are never stored on the shared organization.
    assert admin.post("/analytics/claude/connect", json={"credential_source": "api_key", "api_key": "sk-ant-api03-test"}).status_code == 403
    assert admin.post("/integrations", json={"connector": "slack", "name": "Slack", "config": {},
                                             "credentials": {"webhook_url": "https://hooks.slack.com/services/x"}}).status_code == 403

    # Addresses are not recorded where other visitors could read them.
    assert all(s["ip_address"] is None for s in admin.ok("GET", "/auth/sessions"))
