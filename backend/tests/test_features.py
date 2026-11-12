"""Connect Claude, platform administration, email verification, proxy handling, stale assets,
engine permissions, and integration code paths that need a local stand-in (SMTP, S3, OTLP, Teams, Gemini)."""

import json
import uuid
from datetime import UTC, datetime, timedelta

import anthropic
import httpx
import httpx2
import pytest
from starlette.requests import Request

from app.core.config import get_settings
from app.integrations.llm import claude
from tests.conftest import PASSWORD, login

# --- Claude -------------------------------------------------------------------------------

MODELS = {"data": [{"type": "model", "id": "claude-opus-5-5", "display_name": "Claude Opus 5.5", "created_at": "2026-09-01T00:00:00Z"},
                   {"type": "model", "id": "claude-haiku-5-5", "display_name": "Claude Haiku 5.5", "created_at": "2026-09-01T00:00:00Z"}],
          "has_more": False, "first_id": "claude-opus-5-5", "last_id": "claude-haiku-5-5"}
ANALYSIS = {"summary": "Stored XSS on an internet-facing page.", "why_it_matters": "The page is internet-exposed.",
            "recommended_actions": ["Encode output"], "evidence_used": ["finding.title"], "caveats": []}


class FakeClaude:
    """Stands in for api.anthropic.com behind the real SDK, recording every request."""

    def __init__(self, valid_key="sk-ant-api03-valid"):
        self.valid_key, self.requests = valid_key, []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        presented = request.headers.get("x-api-key") or request.headers.get("authorization", "").removeprefix("Bearer ")
        if presented != self.valid_key:
            return httpx2.Response(401, json={"type": "error", "error": {"type": "authentication_error", "message": "invalid x-api-key"}})
        if request.url.path == "/v1/models":
            return httpx2.Response(200, json=MODELS)
        if request.url.path == "/v1/messages":
            body = json.loads(request.content)
            return httpx2.Response(200, json={
                "id": "msg_1", "type": "message", "role": "assistant", "model": body["model"], "stop_reason": "end_turn", "stop_sequence": None,
                "content": [{"type": "thinking", "thinking": "", "signature": "sig"}, {"type": "text", "text": json.dumps(ANALYSIS)}],
                "usage": {"input_tokens": 1200, "output_tokens": 300}})
        return httpx2.Response(404, json={"type": "error", "error": {"type": "not_found_error", "message": "no"}})


@pytest.fixture
def fake_claude(monkeypatch):
    fake = FakeClaude()
    real = claude.make_client

    def make(config, credentials):
        real(config, credentials)  # keep the real validation (server-credential gate, missing key)
        return anthropic.Anthropic(api_key=credentials.api_key or "server", max_retries=0,
                                   http_client=anthropic.DefaultHttpxClient(transport=httpx2.MockTransport(fake)))

    monkeypatch.setattr(claude, "make_client", make)
    return fake


def test_connect_claude_and_use_ai_features(org, make_user, fake_claude, drain):
    status = org.ok("GET", "/analytics/claude")
    assert status["connected"] is False and "do not include API access" in status["billing_note"]
    analyst = make_user(org, "security_analyst")
    assert analyst.post("/analytics/claude/connect", json={"api_key": "sk-ant-api03-valid"}).status_code == 403  # org admins only

    bad = org.post("/analytics/claude/connect", json={"api_key": "sk-ant-api03-wrong", "model": "claude-opus-5-5"})
    assert bad.status_code == 422 and "rejected the credentials" in bad.json()["error"]["message"]
    missing = org.post("/analytics/claude/connect", json={"api_key": "sk-ant-api03-valid", "model": "claude-fable-9"})
    assert missing.status_code == 422 and len(missing.json()["error"]["details"]["models"]) == 2  # offers the real list
    assert org.post("/analytics/claude/connect", json={"credential_source": "server"}).status_code == 422  # not allowed by default

    connected = org.ok("POST", "/analytics/claude/connect", json={"api_key": "sk-ant-api03-valid", "model": "claude-opus-5-5", "effort": "high"})
    assert connected["connected"] and connected["in_use"] and connected["has_api_key"] and [m["id"] for m in connected["models"]] == ["claude-opus-5-5", "claude-haiku-5-5"]
    assert "sk-ant-api03-valid" not in json.dumps(org.ok("GET", "/integrations")) + json.dumps(connected)
    # Reconnecting with a new model keeps the stored key.
    org.ok("POST", "/analytics/claude/connect", json={"model": "claude-haiku-5-5"})
    org.ok("POST", "/analytics/claude/connect", json={"model": "claude-opus-5-5", "effort": "high"})
    assert [m["id"] for m in org.ok("GET", "/analytics/claude/models")] == ["claude-opus-5-5", "claude-haiku-5-5"]
    assert org.ok("POST", "/analytics/claude/test")["ok"] is True

    asset = org.ok("POST", "/assets", json={"type": "website", "identifier": "https://ai.acme.test", "name": "Portal", "exposure": "internet"})
    finding = org.ok("POST", "/findings", json={"asset_id": asset["id"], "title": "Stored XSS", "severity": "high", "domain": "web"})
    result = org.ok("POST", f"/analytics/findings/{finding['id']}/explain")
    assert result["analysis"] == ANALYSIS and result["model"] == "claude-opus-5-5" and result["usage"]["cost_usd"] == round((1200 * 4 + 300 * 20) / 1e6, 6)
    sent = json.loads(fake_claude.requests[-1].content)
    assert sent["model"] == "claude-opus-5-5" and sent["output_config"] == {"effort": "high"} and sent["fallbacks"] == "default"
    assert "server-side-fallback-2026-07-01" in fake_claude.requests[-1].headers["anthropic-beta"]
    assert "thinking" not in sent and "temperature" not in sent and "<platform_data>" in sent["messages"][0]["content"]
    briefing = org.ok("POST", "/analytics/briefing")
    assert briefing["ai_generated"] and "Write an executive briefing" in json.loads(fake_claude.requests[-1].content)["messages"][0]["content"]
    assert analyst.ok("POST", f"/analytics/findings/{finding['id']}/explain")["analysis"]["summary"]  # analysts can use it

    org.ok("DELETE", "/analytics/claude", expected=204)
    assert org.ok("GET", "/analytics/claude")["connected"] is False
    assert org.post(f"/analytics/findings/{finding['id']}/explain").status_code == 409


def test_server_claude_credentials_when_the_deployment_allows_them(org, fake_claude, monkeypatch):
    monkeypatch.setattr(get_settings(), "allow_server_claude_credentials", True)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-api03-valid")
    fake_claude.valid_key = "server"  # the fixture's stand-in for the SDK's default credential chain
    status = org.ok("POST", "/analytics/claude/connect", json={"credential_source": "server"})
    assert status["credential_source"] == "server" and status["has_api_key"] is False


def test_claude_error_mapping():
    def raise_(exc):
        def f():
            raise exc
        return f

    request = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")
    low = anthropic.BadRequestError("Your credit balance is too low", response=httpx2.Response(400, request=request), body=None)
    with pytest.raises(claude.ApiError, match="no API credits"):
        claude.call(raise_(low))
    rate = anthropic.RateLimitError("slow down", response=httpx2.Response(429, request=request), body=None)
    with pytest.raises(claude.ApiError) as err:
        claude.call(raise_(rate))
    assert err.value.error_class == "rate_limit"


# --- Platform administration ----------------------------------------------------------------

def test_platform_operator_can_suspend_and_reinstate_organizations(make_org, app):
    from app import cli

    operator, other = make_org("Operator"), make_org("Customer")
    assert operator.get("/platform/organizations").status_code == 403
    cli.grant_super_admin(operator.email)
    operator = login(app, operator.email)
    orgs = {o["id"]: o for o in operator.ok("GET", "/platform/organizations")}
    assert orgs[other.org_id]["users"] == 1 and orgs[other.org_id]["is_active"]
    assert "findings" in orgs[other.org_id] and "items" not in orgs[other.org_id]
    assert operator.patch(f"/platform/organizations/{operator.org_id}", json={"is_active": False}).status_code == 403
    operator.ok("PATCH", f"/platform/organizations/{other.org_id}", json={"is_active": False})
    assert other.get("/auth/me").status_code == 401  # sessions ended
    from fastapi.testclient import TestClient

    assert TestClient(app).post("/api/v1/auth/login", json={"email": other.email, "password": PASSWORD}).status_code == 401
    operator.ok("PATCH", f"/platform/organizations/{other.org_id}", json={"is_active": True})
    assert login(app, other.email).get("/auth/me").status_code == 200
    assert operator.get(f"/findings?organization_id={other.org_id}").json()["total"] == 0  # no cross-tenant data access


# --- Email verification ----------------------------------------------------------------------

def test_email_verification_can_be_required(org, monkeypatch):
    from tests.test_auth import _inject_token

    monkeypatch.setattr(get_settings(), "require_email_verification", True)
    blocked = org.get("/assets")
    assert blocked.status_code == 403 and blocked.json()["error"]["details"]["email_unverified"] is True
    me = org.ok("GET", "/auth/me")
    assert me["email_verified"] is False and me["email_verification_required"] is True
    assert org.ok("POST", "/auth/email/resend", expected=202)["detail"]
    token = _inject_token(org.email, "verify_email")
    from fastapi.testclient import TestClient

    from app.main import app as main_app

    assert TestClient(main_app).post("/api/v1/auth/email/verify", json={"token": token}).status_code == 204
    assert org.get("/assets").status_code == 200 and org.ok("GET", "/auth/me")["email_verified"] is True


# --- Client address behind proxies -------------------------------------------------------

def _request(peer: str, xff: str | None) -> Request:
    headers = [(b"x-forwarded-for", xff.encode())] if xff else []
    return Request({"type": "http", "client": (peer, 1234), "headers": headers, "method": "GET", "path": "/"})


def test_client_ip_uses_forwarded_for_only_from_trusted_proxies():
    from app.core.clientip import client_ip

    assert client_ip(_request("127.0.0.1", "203.0.113.7")) == "203.0.113.7"  # Next.js proxy on loopback
    assert client_ip(_request("198.51.100.9", "203.0.113.7")) == "198.51.100.9"  # direct client cannot claim an address
    assert client_ip(_request("127.0.0.1", "6.6.6.6, 203.0.113.7")) == "203.0.113.7"  # spoofed left-most entry is ignored
    assert client_ip(_request("127.0.0.1", "garbage")) == "127.0.0.1"
    assert client_ip(_request("127.0.0.1", None)) == "127.0.0.1"


def test_rate_limit_is_per_client_behind_the_proxy(app, monkeypatch):
    from fastapi.testclient import TestClient

    from app.core import ratelimit

    ratelimit.reset_local()
    monkeypatch.setattr(get_settings(), "rate_limit_auth", 2)
    http = TestClient(app, client=("127.0.0.1", 50000))
    body = {"email": "nobody@example.com", "password": "x" * 14}
    a = [http.post("/api/v1/auth/login", json=body, headers={"X-Forwarded-For": "203.0.113.1"}).status_code for _ in range(3)]
    b = http.post("/api/v1/auth/login", json=body, headers={"X-Forwarded-For": "203.0.113.2"}).status_code
    ratelimit.reset_local()
    assert a == [401, 401, 429] and b == 401  # one user's failures do not lock out another


# --- Assets, permissions, notifications ---------------------------------------------------

def test_stale_assets_and_discovery_notifications(org, db_for, drain):
    from app.domains.assets.service import AssetSpec, upsert_asset
    from app.models import Asset
    from app.workers.queue import enqueue

    with db_for(org) as db:
        found, _ = upsert_asset(db, AssetSpec(type="subdomain", identifier="old.stale.test", exposure="internet"), source="dns_discovery")
        manual, _ = upsert_asset(db, AssetSpec(type="host", identifier="db-1.stale.test"), source="manual")
        for a in (found, manual):
            db.get(Asset, a.id).last_seen_at = datetime.now(UTC) - timedelta(days=45)
        enqueue(db, organization_id=uuid.UUID(org.org_id), job_type="assets.mark_stale")
    drain()
    assert org.ok("GET", f"/assets/{found.id}")["status"] == "stale"
    assert org.ok("GET", f"/assets/{manual.id}")["status"] == "active"  # manually registered assets are exempt
    assert org.ok("GET", f"/assets/{found.id}/history")["items"][0]["event_type"] == "stale"
    assert any(n["event_type"] == "asset.discovered" and n["entity_id"] == str(found.id) for n in org.ok("GET", "/notifications")["items"])
    with db_for(org) as db:  # re-observation reactivates
        upsert_asset(db, AssetSpec(type="subdomain", identifier="old.stale.test"), source="dns_discovery")
    assert org.ok("GET", f"/assets/{found.id}")["status"] == "active"


def test_discovery_engines_require_discovery_permission(org, make_user):
    org.ok("POST", "/scope", json={"kind": "domain", "value": "perm.example", "authorization_note": "Permission check domain"})
    manager = make_user(org, "vulnerability_manager")  # has assessments:run but not discovery:run
    r = manager.post("/assessments", json={"name": "dns", "kind": "dns_discovery", "targets": [{"kind": "domain", "value": "perm.example"}]})
    assert r.status_code == 403 and r.json()["error"]["details"]["missing"] == ["discovery:run"]
    analyst = make_user(org, "security_analyst")
    a = analyst.ok("POST", "/assessments", json={"name": "dns", "kind": "dns_discovery", "targets": [{"kind": "domain", "value": "perm.example"}]})
    assert manager.patch(f"/assessments/{a['id']}", json={"enabled": False}).status_code == 403
    analyst.ok("PATCH", f"/assessments/{a['id']}", json={"enabled": False, "schedule_interval_minutes": 60})
    analyst.ok("DELETE", f"/assessments/{a['id']}", expected=204)


def test_catalog_describes_how_each_integration_is_used(org):
    catalog = {c["key"]: c for c in org.ok("GET", "/integrations/catalog")}
    assert not ({"azure", "gcp", "aws_bedrock", "huggingface"} & set(catalog))  # no entries without an implementation
    assert all("status" not in c and "live_validated" not in c for c in catalog.values())
    assert {catalog[k]["mode"] for k in ("aws", "jira", "slack", "llm")} == {"connection"}
    assert catalog["trivy"]["mode"] == "tool" and catalog["trivy"]["import_format"] == "trivy"
    assert catalog["prowler"]["mode"] == "upload" and catalog["cisa_kev"]["mode"] == "feed"
    assert catalog["claude"]["configurable"] is False
    assert org.post("/integrations", json={"connector": "claude", "name": "x"}).status_code == 422  # managed through Connect Claude


# --- Channels and infrastructure that need local stand-ins -----------------------------------

def test_email_delivery_over_smtp(org, drain, monkeypatch):
    from aiosmtpd.controller import Controller

    received = []

    class Sink:
        async def handle_DATA(self, server, session, envelope):
            received.append((envelope.rcpt_tos, envelope.content.decode()))
            return "250 OK"

    import socket

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    controller = Controller(Sink(), hostname="127.0.0.1", port=port)
    controller.start()
    try:
        for key, value in (("smtp_host", "127.0.0.1"), ("smtp_port", port), ("smtp_starttls", False)):
            monkeypatch.setattr(get_settings(), key, value)
        from fastapi.testclient import TestClient

        from app.main import app as main_app

        assert TestClient(main_app).post("/api/v1/auth/password/forgot", json={"email": org.email}).status_code == 202
        org.ok("POST", "/notifications/rules", json={"name": "Mail", "channel": "email", "email_to": "soc@example.com", "min_severity": "high"})
        asset = org.ok("POST", "/assets", json={"type": "website", "identifier": "https://mail.acme.test", "name": "M", "exposure": "internet", "criticality": "critical"})
        org.ok("POST", "/findings", json={"asset_id": asset["id"], "title": "RCE", "severity": "critical", "domain": "web", "confidence": "confirmed"})
        drain()
    finally:
        controller.stop()
    reset = next(body for rcpt, body in received if rcpt == [org.email])
    assert "Reset your password" in reset and "/reset-password?token=" in reset
    alert = next(body for rcpt, body in received if rcpt == ["soc@example.com"])
    assert "[CTEM][CRITICAL]" in alert and "RCE" in alert


def test_teams_and_slack_payloads(org, drain, monkeypatch, site):
    monkeypatch.setattr(get_settings(), "allow_private_webhooks", True)
    site.routes["/teams"] = (202, {}, b"")
    site.routes["/slack"] = (200, {}, b"ok")
    teams = org.ok("POST", "/integrations", json={"connector": "teams", "name": "Teams", "config": {"url": site.url + "/teams"}})
    slack = org.ok("POST", "/integrations", json={"connector": "slack", "name": "Slack", "config": {"url": site.url + "/slack"}})
    assert org.ok("POST", f"/integrations/{teams['id']}/test")["ok"] and org.ok("POST", f"/integrations/{slack['id']}/test")["ok"]
    card = json.loads(next(b for m, p, h, b in site.requests if p == "/teams"))
    assert card["type"] == "message" and card["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"
    assert card["attachments"][0]["content"]["type"] == "AdaptiveCard" and card["attachments"][0]["content"]["actions"][0]["type"] == "Action.OpenUrl"
    block = json.loads(next(b for m, p, h, b in site.requests if p == "/slack"))
    assert block["blocks"][0]["type"] == "section" and block["text"].startswith("[INFO]")


def test_s3_evidence_storage(monkeypatch):
    import boto3
    from moto import mock_aws

    from app.core import storage

    with mock_aws():
        boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="ctem-evidence")
        store = storage.S3Storage("ctem-evidence", None, "us-east-1")
        store.put("org/evidence/a.txt", b"proof", "text/plain")
        assert store.get("org/evidence/a.txt") == b"proof"
        head = boto3.client("s3", region_name="us-east-1").head_object(Bucket="ctem-evidence", Key="org/evidence/a.txt")
        assert head["ServerSideEncryption"] == "AES256"
        store.delete("org/evidence/a.txt")
        with pytest.raises(storage.NotFound):
            store.get("org/evidence/a.txt")


def test_opentelemetry_exports_spans(site, monkeypatch):
    from fastapi.testclient import TestClient
    from opentelemetry import trace

    site.routes["/v1/traces"] = (200, {}, b"")
    monkeypatch.setattr(get_settings(), "otel_exporter_otlp_endpoint", site.url)
    from app.main import create_app

    TestClient(create_app()).get("/api/v1/auth/me")
    provider = trace.get_tracer_provider()
    provider.force_flush()
    exports = [({k.lower(): v for k, v in h.items()}, b) for m, p, h, b in site.requests if p == "/v1/traces"]
    provider.shutdown()  # stop the background exporter before the collector goes away
    assert exports and exports[0][0]["content-type"] == "application/x-protobuf" and b"/api/v1/auth/me" in exports[0][1]


def test_gemini_client_request_shape(monkeypatch):
    from app.integrations.llm import client as llm

    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": "OK"}]}, "finishReason": "STOP"}],
                                         "usageMetadata": {"promptTokenCount": 5, "candidatesTokenCount": 1}})

    monkeypatch.setattr(llm, "TRANSPORT", httpx.MockTransport(handler))
    config = llm.LlmConfig(api_style="gemini", base_url="https://generativelanguage.googleapis.com/v1beta", model="gemini-2.5-pro")
    result = llm.build_client(config, llm.LlmCredentials(api_key="g-key")).chat("hi", system="be brief", max_tokens=10)
    assert result.text == "OK" and result.input_tokens == 5
    assert seen[0].url.path == "/v1beta/models/gemini-2.5-pro:generateContent" and seen[0].headers["x-goog-api-key"] == "g-key"
    assert json.loads(seen[0].content)["systemInstruction"]["parts"][0]["text"] == "be brief"


def test_operations_cli(org, capsys):
    from app import cli
    from app.db.session import system_session
    from app.models import Organization

    org.ok("POST", "/integrations", json={"connector": "webhook", "name": "hook", "config": {"url": "https://h.example.com/x"}, "credentials": {"signing_secret": "abc123456"}})
    with system_session() as db:
        slug = db.get(Organization, uuid.UUID(org.org_id)).slug
    with pytest.raises(SystemExit) as done:
        cli.verify_audit(slug)
    assert done.value.code == 0 and "'valid': True" in capsys.readouterr().out
    cli.rotate_secrets()
    assert "Re-encrypted" in capsys.readouterr().out
    assert org.ok("GET", "/integrations")[0]["has_credentials"] is True


# --- Invitations and unrecorded AI posture -------------------------------------------------

def test_invited_user_sets_own_password(app, org):
    from urllib.parse import parse_qs, urlparse

    from fastapi.testclient import TestClient

    roles = {r["key"]: r["id"] for r in org.ok("GET", "/admin/roles")}
    email = f"invitee-{uuid.uuid4().hex[:8]}@example.com"
    created = org.ok("POST", "/admin/users", json={"email": email, "full_name": "Invitee", "role_id": roles["security_analyst"]})
    link = created["invite_link"]
    assert link and "/reset-password?token=" in link
    # nobody knows a password for the account until the invitee picks one
    assert TestClient(app).post("/api/v1/auth/login", json={"email": email, "password": PASSWORD}).status_code == 401
    # re-issuing invalidates the first link
    second = org.ok("POST", f"/admin/users/{created['id']}/invite")["invite_link"]
    first_token = parse_qs(urlparse(link).query)["token"][0]
    token = parse_qs(urlparse(second).query)["token"][0]
    http = TestClient(app)
    assert http.post("/api/v1/auth/password/reset", json={"token": first_token, "new_password": "An0ther-long-passphrase!"}).status_code >= 400
    assert http.post("/api/v1/auth/password/reset", json={"token": token, "new_password": "An0ther-long-passphrase!"}).status_code == 204
    me = login(app, email, "An0ther-long-passphrase!").get("/auth/me").json()
    assert me["email_verified"] is True


def test_rag_app_added_as_asset_is_assessed(org, drain):
    asset = org.ok("POST", "/assets", json={"type": "rag_application", "name": "support-rag", "identifier": "rag://support",
                                            "exposure": "internet", "environment": "production", "criticality": "high"})
    assert any(a["id"] == asset["id"] for a in org.ok("GET", "/ai/assets")["items"])
    drain()
    findings = org.ok("GET", "/findings", params={"asset_id": asset["id"], "page_size": 100})["items"]
    rules = {f["rule_id"] for f in findings}
    assert "ai.posture.unrecorded" in rules, rules
    gap = next(f for f in findings if f["rule_id"] == "ai.posture.unrecorded")
    assert gap["severity"] == "medium"


def test_recording_posture_resolves_gap_findings(org, drain):
    asset = org.ok("POST", "/ai/assets", json={"type": "rag_application", "name": "hr-rag", "identifier": "rag://hr",
                                               "exposure": "internet", "environment": "production"})
    drain()
    rules = lambda status: {f["rule_id"] for f in org.ok("GET", "/findings", params={"asset_id": asset["id"], "status": status})["items"]}  # noqa: E731
    assert "ai.posture.unrecorded" in rules("new")
    org.ok("PATCH", f"/ai/assets/{asset['id']}", json={"auth_required": False})
    drain()
    assert "ai.rag.vector_db_exposed" in rules("new")
    org.ok("PATCH", f"/ai/assets/{asset['id']}", json={"auth_required": True, "tenant_isolation": "enforced", "document_level_authorization": True,
                                                       "ingests_untrusted_content": False})
    drain()
    assert {"ai.posture.unrecorded", "ai.rag.vector_db_exposed"} <= rules("remediated")
    assert not {"ai.posture.unrecorded", "ai.rag.vector_db_exposed"} & rules("new")


def test_streaming_array_decoder_matches_json_loads():
    from app.integrations.intel.sources import iter_array_items

    objects = [{"type": "attack-pattern", "id": i, "description": "naïve “quoted” " + "x" * (i * 37 % 4000)} for i in range(500)]
    data = json.dumps({"type": "bundle", "id": "b", "objects": objects}, ensure_ascii=False).encode()
    for chunk in (7, 333, 1 << 12):  # small chunks split objects and multi-byte characters
        assert list(iter_array_items(data, "objects", chunk=chunk)) == objects
    assert list(iter_array_items(b'{"objects": [ ]}', "objects")) == []
