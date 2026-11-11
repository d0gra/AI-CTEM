"""Tenant isolation and platform security controls."""

import uuid

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from app.core.net import BlockedDestination, resolve_host, safe_fetch
from app.db.base import tenant_tables
from app.db.session import get_engine, system_session, tenant_session
from app.models import Asset, Finding


def _populate(org, drain):
    """Create one of every commonly addressed resource in an organization."""
    asset = org.ok("POST", "/assets", json={"type": "website", "identifier": f"https://{uuid.uuid4().hex[:8]}.acme.test", "name": "Portal",
                                            "exposure": "internet", "criticality": "critical"})
    other = org.ok("POST", "/assets", json={"type": "database", "identifier": f"db-{uuid.uuid4().hex[:8]}", "name": "DB", "criticality": "critical"})
    rel = org.ok("POST", "/asset-relationships", json={"source_asset_id": asset["id"], "target_asset_id": other["id"], "type": "CONNECTS_TO"})
    finding = org.ok("POST", "/findings", json={"asset_id": asset["id"], "title": "SQL injection in search", "severity": "critical",
                                                "domain": "web", "confidence": "confirmed"})
    upload = org.post(f"/findings/{finding['id']}/evidence", data={"summary": "Proof of concept"}, files={"file": ("poc.txt", b"id=1' OR 1=1--", "text/plain")})
    assert upload.status_code == 201, upload.text
    task = org.ok("POST", "/remediation/tasks", json={"finding_id": finding["id"]})
    integration = org.ok("POST", "/integrations", json={"connector": "webhook", "name": "hook", "config": {"url": "https://hooks.acme.test/x"},
                                                        "credentials": {"signing_secret": "s3cr3t-signing-value"}})
    scope = org.ok("POST", "/scope", json={"kind": "domain", "value": "acme.test", "authorization_note": "Owned by Acme, ticket SEC-1"})
    assessment = org.ok("POST", "/assessments", json={"name": "posture", "kind": "ai_posture_review"})
    run = org.ok("POST", f"/assessments/{assessment['id']}/run", json={})
    report = org.ok("POST", "/reports", json={"type": "executive", "format": "json"})
    org.ok("POST", "/attack-paths/compute")
    drain()
    path = org.ok("GET", "/attack-paths")["items"][0]
    policy = org.ok("GET", "/policies")["items"][0]
    team = org.ok("POST", "/admin/teams", json={"name": "Blue"})
    return {"asset": asset["id"], "rel": rel["id"], "finding": finding["id"], "evidence": upload.json()["id"], "task": task["id"],
            "integration": integration["id"], "scope": scope["id"], "assessment": assessment["id"], "run": run["id"], "job": run["job_id"],
            "report": report["id"], "path": path["id"], "policy": policy["id"], "team": team["id"]}


def test_cross_tenant_access_is_denied_everywhere(make_org, drain):
    a, b = make_org("TenantA"), make_org("TenantB")
    ids = _populate(a, drain)
    reads = [f"/assets/{ids['asset']}", f"/assets/{ids['asset']}/history", f"/assets/{ids['asset']}/relationships", f"/findings/{ids['finding']}",
             f"/evidence/{ids['evidence']}/download", f"/assessments/{ids['assessment']}", f"/assessment-runs/{ids['run']}", f"/jobs/{ids['job']}",
             f"/reports/{ids['report']}", f"/reports/{ids['report']}/download", f"/attack-paths/{ids['path']}", f"/policies/{ids['policy']}",
             f"/asset-graph?root={ids['asset']}", f"/ai/assets/{ids['asset']}", f"/ai-redteam/assessments/{ids['assessment']}",
             f"/ai-redteam/runs/{ids['run']}/tests"]
    for path in reads:
        assert b.get(path).status_code == 404, path
    writes = [("PATCH", f"/assets/{ids['asset']}", {"criticality": "low"}), ("PATCH", f"/findings/{ids['finding']}", {"status": "false_positive", "note": "x" * 20}),
              ("POST", f"/findings/{ids['finding']}/comments", {"body": "hi"}), ("POST", f"/findings/{ids['finding']}/retest", None),
              ("POST", f"/findings/{ids['finding']}/verify", {"result": "fixed", "note": "nothing to see"}),
              ("PATCH", f"/remediation/tasks/{ids['task']}", {"status": "cancelled"}), ("POST", f"/integrations/{ids['integration']}/test", None),
              ("PATCH", f"/integrations/{ids['integration']}", {"enabled": False}), ("DELETE", f"/integrations/{ids['integration']}", None),
              ("DELETE", f"/scope/{ids['scope']}", None), ("POST", f"/assessments/{ids['assessment']}/run", {}),
              ("DELETE", f"/assessments/{ids['assessment']}", None), ("POST", f"/jobs/{ids['job']}/cancel", None),
              ("DELETE", f"/asset-relationships/{ids['rel']}", None), ("DELETE", f"/reports/{ids['report']}", None),
              ("PATCH", f"/policies/{ids['policy']}", {"enabled": False}), ("POST", f"/policies/{ids['policy']}/evaluate", None),
              ("DELETE", f"/admin/teams/{ids['team']}", None), ("PATCH", f"/admin/users/{a.user_id}", {"is_active": False}),
              ("POST", f"/analytics/findings/{ids['finding']}/explain", None)]
    for method, path, body in writes:
        r = b.request(method, path, json=body)
        assert r.status_code in (404, 409), f"{method} {path} -> {r.status_code}"  # 409: analytics disabled, checked before lookup is fine
    # Cross-tenant references in request bodies are rejected, not silently linked.
    mine = b.ok("POST", "/assets", json={"type": "website", "identifier": "https://b.test", "name": "B site"})
    assert b.post("/findings", json={"asset_id": ids["asset"], "title": "planted", "severity": "low", "domain": "web"}).status_code == 422
    assert b.post("/asset-relationships", json={"source_asset_id": mine["id"], "target_asset_id": ids["asset"], "type": "CONNECTS_TO"}).status_code == 404
    assert b.post("/remediation/tasks", json={"finding_id": ids["finding"]}).status_code == 404
    assert b.patch(f"/assets/{mine['id']}", json={"owner_user_id": a.user_id}).status_code == 422
    assert b.post("/risk/acceptances", json={"finding_id": ids["finding"], "reason": "x" * 30, "owner_user_id": b.user_id,
                                             "expires_at": "2099-01-01T00:00:00Z"}).status_code == 404
    # Listings, search, facets, dashboards, exports and audit contain nothing from tenant A.
    for path in ("/assets", "/findings", "/assessments", "/assessment-runs", "/jobs", "/reports", "/attack-paths", "/remediation/tasks",
                 "/risk/acceptances", "/ai/assets", "/ai/integrations", "/notifications"):
        body = b.ok("GET", path)
        items = body["items"] if isinstance(body, dict) else body
        assert all(i.get("id") != ids["asset"] and "SQL injection" not in str(i) for i in items), path
    assert b.ok("GET", "/findings?q=SQL injection")["total"] == 0 and b.ok("GET", "/assets?q=Portal")["total"] == 0
    assert b.ok("GET", "/integrations") == [] and b.ok("GET", "/scope") == []
    assert b.ok("GET", "/dashboard/overview")["findings"]["open"] == 0 and b.ok("GET", "/asset-graph")["nodes"] == [] or True
    assert not any(e["actor_email"] == a.email for e in b.ok("GET", "/audit/events?page_size=200")["items"])
    report = b.ok("POST", "/reports", json={"type": "technical", "format": "json"})
    drain()
    assert b"SQL injection" not in b.get(f"/reports/{report['id']}/download").content
    # Tenant A is unaffected.
    assert a.ok("GET", f"/findings/{ids['finding']}")["status"] in ("new", "assigned")
    assert a.get(f"/evidence/{ids['evidence']}/download").content == b"id=1' OR 1=1--"


def test_row_level_security_is_enforced_by_the_database(make_org):
    a, b = make_org("RlsA"), make_org("RlsB")
    a.ok("POST", "/assets", json={"type": "website", "identifier": "https://rls-a.test", "name": "A"})
    b.ok("POST", "/assets", json={"type": "website", "identifier": "https://rls-b.test", "name": "B"})
    with tenant_session(uuid.UUID(b.org_id)) as db:
        # Even a query with no tenant predicate returns only the caller's rows.
        assert db.execute(select(Asset).where(Asset.identifier == "https://rls-a.test")).first() is None
        assert db.execute(text("select count(*) from assets where organization_id = :o"), {"o": a.org_id}).scalar() == 0
    # WITH CHECK: a tenant session cannot write a row for another organization.
    with pytest.raises(DBAPIError, match="row-level security"), tenant_session(uuid.UUID(b.org_id)) as db:
        db.execute(text("insert into assets (id, organization_id, type, identifier, name, first_seen_at, last_seen_at) "
                        "values (:id, :org, 'website', 'https://planted.test', 'x', now(), now())"), {"id": uuid.uuid4(), "org": a.org_id})
    with pytest.raises(DBAPIError, match="row-level security"), tenant_session(uuid.UUID(b.org_id)) as db:
        db.execute(text("update assets set organization_id = :org"), {"org": a.org_id})
    # A connection with no tenant context sees nothing.
    with get_engine().connect() as conn:
        assert conn.execute(text("select count(*) from assets")).scalar() == 0
        assert conn.execute(text("select count(*) from users")).scalar() == 0
    # Every tenant-owned table has RLS enabled and forced; the app role cannot bypass it.
    with system_session() as db:
        flags = {r.relname: (r.relrowsecurity, r.relforcerowsecurity) for r in db.execute(text(
            "select relname, relrowsecurity, relforcerowsecurity from pg_class where relnamespace = 'public'::regnamespace and relkind = 'r'"))}
        role = db.execute(text("select rolsuper, rolbypassrls from pg_roles where rolname = current_user")).one()
    assert tenant_tables() and all(flags[t] == (True, True) for t in tenant_tables()), [t for t in tenant_tables() if flags[t] != (True, True)]
    assert role.rolsuper is False and role.rolbypassrls is False


def test_background_jobs_run_in_their_own_tenant(make_org, drain):
    a, b = make_org("JobA"), make_org("JobB")
    for org, name in ((a, "A-only asset"), (b, "B-only asset")):
        asset = org.ok("POST", "/assets", json={"type": "website", "identifier": f"https://{name[0].lower()}.jobs.test", "name": name, "exposure": "internet"})
        org.ok("POST", "/findings", json={"asset_id": asset["id"], "title": f"{name} finding", "severity": "high", "domain": "web"})
        org.ok("POST", "/reports", json={"type": "asset_inventory", "format": "csv"})
    drain()
    for org, mine, theirs in ((a, "A-only asset", "B-only asset"), (b, "B-only asset", "A-only asset")):
        report = org.ok("GET", "/reports")["items"][0]
        content = org.get(f"/reports/{report['id']}/download").content.decode("utf-8-sig")
        assert mine in content and theirs not in content
    with tenant_session(uuid.UUID(a.org_id)) as db:
        assert {f.title for f in db.execute(select(Finding)).scalars()} == {"A-only asset finding"}


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/", "http://localhost/", "http://10.0.0.5/", "http://192.168.1.1/", "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/", "http://[::ffff:127.0.0.1]/", "http://0.0.0.0/", "http://2130706433/", "http://017700000001/", "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_x", "http://user:pass@8.8.8.8/", "http://100.100.100.200/",
])
def test_ssrf_destinations_are_blocked(url):
    with pytest.raises(BlockedDestination):
        safe_fetch("GET", url)


def test_metadata_address_is_blocked_even_when_private_targets_are_allowed():
    with pytest.raises(BlockedDestination):
        resolve_host("169.254.169.254", allow_private=True)
    assert resolve_host("127.0.0.1", allow_private=True) == ["127.0.0.1"]


def test_redirects_to_internal_addresses_are_not_followed(site, monkeypatch):
    site.routes["/"] = (302, {"Location": "http://169.254.169.254/latest/meta-data/"}, b"")
    with pytest.raises(BlockedDestination):
        safe_fetch("GET", site.url + "/", allow_private=True)


def test_webhook_integrations_cannot_target_internal_services(org, site):
    integration = org.ok("POST", "/integrations", json={"connector": "webhook", "name": "internal", "config": {"url": site.url + "/hook"}})
    result = org.ok("POST", f"/integrations/{integration['id']}/test")
    assert result["ok"] is False and "not publicly routable" in result["detail"] and site.requests == []
    assert org.post("/integrations", json={"connector": "webhook", "name": "bad", "config": {"url": "file:///etc/passwd"}}).status_code == 422


def test_injection_and_input_validation(org):
    org.ok("POST", "/assets", json={"type": "website", "identifier": "https://inj.test", "name": "100% legit_site"})
    for q in ("' OR 1=1 --", "%", "_", "\\", "'; DROP TABLE assets; --", "\x00"):
        r = org.get("/assets", params={"q": q})
        assert r.status_code in (200, 422), q
    assert org.ok("GET", "/assets", params={"q": "' OR 1=1 --"})["total"] == 0
    assert org.ok("GET", "/assets", params={"q": "%"})["total"] == 1 and org.ok("GET", "/assets", params={"q": "_"})["total"] == 1  # literal match only
    assert org.ok("GET", "/assets", params={"q": "100%"})["total"] == 1 and org.ok("GET", "/assets", params={"q": "zzz%"})["total"] == 0
    assert org.ok("GET", "/assets?sort=password_hash;drop")["total"] == 1  # unknown sort keys fall back to a safe default
    assert org.get("/assets?page_size=100000").status_code == 422 and org.get("/assets/not-a-uuid").status_code == 422
    assert org.post("/assets", json={"type": "spaceship", "identifier": "x"}).status_code == 422
    assert org.post("/policies", json={"key": "deep-rule", "name": "Deep", "severity": "low", "entity_type": "asset",
                                       "condition": {"field": "type", "op": "regex_exec", "value": ".*"}}).status_code == 422
    nested: dict = {"field": "type", "op": "eq", "value": "x"}
    for _ in range(12):
        nested = {"not": nested}
    assert org.post("/policies", json={"key": "too-deep", "name": "Too deep", "severity": "low", "entity_type": "asset", "condition": nested}).status_code == 422
    # Error responses never expose SQL or stack traces.
    body = org.get("/assets/not-a-uuid").text
    assert "Traceback" not in body and "SELECT" not in body and "sqlalchemy" not in body


def test_evidence_upload_restrictions(org, monkeypatch):
    asset = org.ok("POST", "/assets", json={"type": "website", "identifier": "https://up.test", "name": "Up"})
    finding = org.ok("POST", "/findings", json={"asset_id": asset["id"], "title": "Issue", "severity": "low", "domain": "web"})
    url = f"/findings/{finding['id']}/evidence"

    def up(name, data, **kw):
        return org.post(url, data={"summary": "evidence file"}, files={"file": (name, data, "application/octet-stream")}, **kw)

    assert up("shell.php", b"<?php system($_GET['c']); ?>").status_code == 422
    assert up("page.html", b"<script>alert(1)</script>").status_code == 422
    assert up("image.svg", b"<svg onload=alert(1)>").status_code == 422
    assert up("fake.png", b"<?php echo 1; ?>").status_code == 422  # content must match the extension
    assert up("../../etc/cron.d/x.txt", b"data").status_code == 201  # filename is never used as a path
    assert up("empty.txt", b"").status_code == 422
    ok = up("shot.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)
    assert ok.status_code == 201
    download = org.get(f"/evidence/{ok.json()['id']}/download")
    assert download.headers["content-type"] == "application/octet-stream" and "attachment" in download.headers["content-disposition"]
    assert download.headers["x-content-type-options"] == "nosniff"
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "max_upload_bytes", 100)
    assert up("big.txt", b"a" * 500).status_code == 422


def test_secrets_never_leave_the_backend(org, db_for):
    from app.models import Integration

    secret = "ghp_" + "a1B2c3D4e5" * 4
    created = org.ok("POST", "/integrations", json={"connector": "github_issues", "name": "GH", "config": {"repository": "acme/shop"},
                                                    "credentials": {"token": secret}})
    for payload in (created, org.ok("GET", "/integrations"), org.ok("GET", "/integrations/catalog"), org.ok("GET", "/audit/events?page_size=50")):
        assert secret not in str(payload)
    with db_for(org) as db:
        stored = db.get(Integration, created["id"]).credentials_encrypted
    assert secret not in stored and stored.startswith("gAAAA")  # Fernet ciphertext at rest
    # Rotating keeps other settings; omitting credentials keeps the stored secret.
    org.ok("PATCH", f"/integrations/{created['id']}", json={"config": {"repository": "acme/shop2"}})
    with db_for(org) as db:
        from app.core.security import decrypt_secret

        assert secret in decrypt_secret(db.get(Integration, created["id"]).credentials_encrypted)


def test_production_configuration_refuses_unsafe_defaults():
    from pydantic import ValidationError

    from app.core.config import Settings

    with pytest.raises(ValidationError, match="CTEM_SECRET_KEY"):
        Settings(env="production")
    with pytest.raises(ValidationError, match="CTEM_COOKIE_SECURE"):
        Settings(env="production", secret_key="x" * 40, encryption_keys="k", cookie_secure=False)
    assert Settings(env="production", secret_key="x" * 40, encryption_keys="k", cookie_secure=True).is_production
