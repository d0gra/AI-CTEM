"""End-to-end CTEM workflow: discover -> inventory -> assess -> score -> attack path ->
remediate -> retest, executed through the public API and the real worker code path."""

import pytest

from app.engines import dns_discovery

ZONE = {
    ("example.test", "A"): ["8.8.8.8"],
    ("example.test", "MX"): ["10 mail.example.test"],
    ("example.test", "TXT"): ["some-verification=abc"],
    ("app.example.test", "A"): ["8.8.4.4"],
    ("staging.example.test", "A"): ["10.1.2.3"],
    ("old.example.test", "CNAME"): ["gone-app.herokuapp.com"],
}
NXDOMAIN = {"gone-app.herokuapp.com"}


def fake_query(name, rtype):
    if name in NXDOMAIN:
        return "nxdomain", []
    values = ZONE.get((name, rtype), [])
    known = any(k[0] == name for k in ZONE)
    return ("ok" if values else ("nodata" if known else "nxdomain")), values


@pytest.fixture
def fake_dns(monkeypatch):
    monkeypatch.setattr(dns_discovery, "query", fake_query)
    monkeypatch.setattr(dns_discovery, "ct_names", lambda domain: ["app.example.test", "old.example.test", "retired.example.test"])


def scope(org, kind, value, **kw):
    return org.ok("POST", "/scope", json={"kind": kind, "value": value, "authorization_note": "Owned by Acme; approved in SEC-1234", **kw})


def run(org, drain, assessment_id, **body):
    run_ = org.ok("POST", f"/assessments/{assessment_id}/run", json=body)
    drain()
    return org.ok("GET", f"/assessment-runs/{run_['id']}")


def test_discovery_inventory_and_findings(org, drain, fake_dns):
    scope(org, "domain", "example.test")
    a = org.ok("POST", "/assessments", json={"name": "EASM example.test", "kind": "dns_discovery",
                                             "targets": [{"kind": "domain", "value": "example.test"}]})
    result = run(org, drain, a["id"])
    assert result["status"] == "succeeded", result
    assert result["summary"]["assets_created"] >= 6 and result["summary"]["ct_names"] == 3

    assets = {x["identifier"]: x for x in org.ok("GET", "/assets?page_size=100")["items"]}
    assert assets["example.test"]["type"] == "domain" and assets["example.test"]["exposure"] == "internet"
    assert assets["app.example.test"]["exposure"] == "internet"
    assert assets["staging.example.test"]["exposure"] == "internal"
    assert assets["staging.example.test"]["environment"] == "staging"  # inferred, not asserted as fact elsewhere
    assert "retired.example.test" not in assets  # in CT but does not resolve: not inventoried
    assert assets["8.8.4.4"]["type"] == "ip_address"

    rels = org.ok("GET", f"/assets/{assets['app.example.test']['id']}/relationships")
    assert {(r["type"], r["target"]["name"]) for r in rels} >= {("RESOLVES_TO", "8.8.4.4")}
    history = org.ok("GET", f"/assets/{assets['app.example.test']['id']}/history")
    assert history["items"][0]["event_type"] == "discovered" and history["items"][0]["source"] == "dns_discovery"

    findings = {f["rule_id"]: f for f in org.ok("GET", "/findings?page_size=100")["items"]}
    assert findings["dns.spf.missing"]["severity"] == "medium"
    assert findings["dns.dmarc.missing"]["asset_name"] == "example.test"
    dangling = findings["dns.cname.dangling"]
    assert dangling["severity"] == "high" and dangling["asset_name"] == "old.example.test"
    detail = org.ok("GET", f"/findings/{dangling['id']}")
    assert detail["evidence"][0]["content"]["cname"] == "gone-app.herokuapp.com"
    assert detail["risk"]["current"]["formula"].startswith("min(100")
    assert detail["due_at"] is not None  # SLA assigned from risk level

    # Re-running is idempotent: no duplicate assets or findings.
    again = run(org, drain, a["id"])
    assert again["summary"]["assets_created"] == 0 and again["summary"]["findings_created"] == 0
    assert org.ok("GET", "/findings?page_size=100")["total"] == len(findings)

    # Search, filter and sort are server-side.
    assert org.ok("GET", "/assets?q=staging")["total"] == 1
    assert org.ok("GET", "/assets?type=ip_address&exposure=internet")["total"] == 2
    assert org.ok("GET", "/findings?severity=high&q=dangling")["total"] == 1


def test_scope_is_enforced(org, fake_dns, drain, allow_private, site):
    scope(org, "domain", "example.test")
    r = org.post("/assessments", json={"name": "probe", "kind": "dns_discovery", "targets": [{"kind": "domain", "value": "victim.org"}]})
    assert r.status_code == 403 and r.json()["error"]["code"] == "out_of_scope"
    # Passive-only authorization does not permit active engines.
    r = org.post("/assessments", json={"name": "probe", "kind": "http_exposure", "targets": [{"kind": "domain", "value": "app.example.test"}]})
    assert r.status_code == 403 and "Active testing" in r.json()["error"]["message"]
    # Scope removed after the assessment was defined: the run fails closed without contacting the target.
    entry = scope(org, "cidr", "127.0.0.0/8", allow_active=True, allow_private_network=True)
    a = org.ok("POST", "/assessments", json={"name": "local", "kind": "http_exposure", "targets": [{"kind": "url", "value": site.url}]})
    org.ok("DELETE", f"/scope/{entry['id']}", expected=204)
    result = run(org, drain, a["id"])
    assert result["status"] == "failed" and "not covered" in result["error"]
    assert site.requests == []


def test_private_targets_need_deployment_and_scope_opt_in(org, drain, site):
    # Scope entry allows private networks, but the deployment switch is off: the request is blocked.
    scope(org, "cidr", "127.0.0.0/8", allow_active=True, allow_private_network=True)
    a = org.ok("POST", "/assessments", json={"name": "local", "kind": "http_exposure", "targets": [{"kind": "url", "value": site.url}]})
    result = run(org, drain, a["id"])
    assert result["status"] == "failed" and "not publicly routable" in result["error"]
    assert site.requests == []


def _vulnerable_site(site):
    def handler(method, path, headers, body):
        if path == "/":
            h = {"Content-Type": "text/html", "Server": "nginx/1.18.0", "Set-Cookie": ["sessionid=abc123; Path=/"]}
            if headers.get("Origin"):
                h["Access-Control-Allow-Origin"] = headers["Origin"]
                h["Access-Control-Allow-Credentials"] = "true"
            return 200, h, b"<html><head><title>Acme Portal</title></head><body>hi</body></html>"
        return None

    site.handler = handler
    site.routes["/.git/HEAD"] = (200, {"Content-Type": "text/plain"}, b"ref: refs/heads/main\n")
    site.routes["/.env"] = (200, {"Content-Type": "text/plain"}, b"DB_HOST=db.internal\nAPI_KEY=sk-live-supersecretvalue1234567890\n")
    site.routes["/metrics"] = (200, {"Content-Type": "text/html"}, b"<html>custom 404 page with 200 status</html>")


def test_assess_score_attack_path_remediate_retest(org, drain, allow_private, site, make_user):
    _vulnerable_site(site)
    scope(org, "cidr", "127.0.0.0/8", allow_active=True, allow_private_network=True)
    a = org.ok("POST", "/assessments", json={"name": "Portal exposure", "kind": "http_exposure",
                                             "targets": [{"kind": "url", "value": site.url}]})

    # Dry run plans without sending traffic.
    dry = run(org, drain, a["id"], dry_run=True)
    assert dry["status"] == "succeeded" and dry["summary"]["plan"] and site.requests == []

    result = run(org, drain, a["id"])
    assert result["status"] == "succeeded", result
    assert 0 < len(site.requests) <= 20  # bounded request budget
    findings = {f["rule_id"]: f for f in org.ok("GET", "/findings?page_size=100")["items"]}
    assert findings["exposure.env_file_exposed"]["severity"] == "critical"
    assert findings["exposure.git_exposed"]["severity"] == "high"
    assert findings["http.cors.reflected_credentials"]["severity"] == "high"
    assert "http.plaintext" in findings and "http.cookie.flags" in findings
    assert "exposure.metrics_exposed" not in findings  # soft-404 content does not match the signature

    env = org.ok("GET", f"/findings/{findings['exposure.env_file_exposed']['id']}")
    excerpt = env["evidence"][0]["content"]["response"]["body_excerpt"]
    assert "supersecretvalue" not in excerpt and "[REDACTED]" in excerpt  # secrets never stored in evidence

    website = org.ok("GET", "/assets?type=website")["items"][0]
    assert website["exposure"] == "internal" and website["risk_score"] > 0

    # Analyst classifies exposure; a crown-jewel database is connected to the site.
    org.ok("PATCH", f"/assets/{website['id']}", json={"exposure": "internet", "criticality": "high"})
    rescored = org.ok("GET", f"/findings/{env['id']}")
    assert rescored["risk_score"] > env["risk_score"]
    db_asset = org.ok("POST", "/assets", json={"type": "database", "identifier": "postgres://orders-db.internal/orders",
                                               "name": "Orders DB", "criticality": "critical",
                                               "data_sensitivity": "restricted", "exposure": "private"})
    org.ok("POST", "/asset-relationships", json={"source_asset_id": website["id"], "target_asset_id": db_asset["id"],
                                                 "type": "CONNECTS_TO", "note": "App connection string"})
    org.ok("POST", "/attack-paths/compute")
    drain()
    paths = org.ok("GET", "/attack-paths")["items"]
    assert len(paths) == 1
    path = org.ok("GET", f"/attack-paths/{paths[0]['id']}")
    # Manually asserted relationship (confidence 0.8) caps the path at "probable" despite a confirmed finding.
    assert path["classification"] == "probable"
    assert [n["role"] for n in path["nodes"]] == ["entry", "target"]
    assert path["nodes"][1]["crosses_trust_boundary"] is True
    assert path["edges"][0]["enabling_finding"]["id"] == env["id"]
    assert path["edges"][0]["technique"] == "T1021"
    assert any(o["type"] == "fix_finding" for o in path["remediation_opportunities"])
    with_path = org.ok("GET", f"/findings/{env['id']}")
    assert any(e["name"] == "attack_path" for e in with_path["risk"]["current"]["escalators"])
    assert with_path["risk_score"] > rescored["risk_score"]

    # Remediation: assign, fix, retest.
    analyst = make_user(org, "security_analyst")
    task = org.ok("POST", "/remediation/tasks", json={"finding_id": env["id"], "assignee_user_id": analyst.user_id})
    assert task["priority"] == "critical" and task["due_at"]
    assert org.ok("GET", f"/findings/{env['id']}")["status"] == "assigned"
    assert analyst.patch(f"/remediation/tasks/{task['id']}", json={"status": "done"}).status_code == 422
    analyst.ok("PATCH", f"/remediation/tasks/{task['id']}", json={"status": "pending_validation"})
    assert org.ok("GET", f"/findings/{env['id']}")["status"] == "pending_validation"

    del site.routes["/.env"]  # the fix
    git = findings["exposure.git_exposed"]
    analyst.ok("PATCH", f"/findings/{git['id']}", json={"status": "in_progress"})
    analyst.ok("POST", f"/findings/{git['id']}/retest")  # claimed fixed, but is not
    drain()
    fixed, not_fixed = org.ok("GET", f"/findings/{env['id']}"), org.ok("GET", f"/findings/{git['id']}")
    assert fixed["status"] == "remediated" and fixed["resolved_at"]
    assert any(e["event_type"] == "retest" and e["data"]["result"] == "not_present" for e in fixed["timeline"])
    assert not_fixed["status"] == "in_progress"
    assert any(e["event_type"] == "retest" and e["data"]["result"] == "still_present" for e in not_fixed["timeline"])
    assert org.ok("GET", f"/remediation/tasks?finding_id={env['id']}")["items"][0]["status"] == "done"

    # The verified fix triggers recomputation: the path is now carried by a remaining open finding.
    drain()
    remaining = org.ok("GET", "/attack-paths")["items"]
    assert len(remaining) == 1
    enabling = org.ok("GET", f"/attack-paths/{remaining[0]['id']}")["edges"][0]["enabling_finding"]
    assert enabling["id"] != env["id"] and enabling["status"] != "remediated"

    # Regression: the file comes back -> the remediated finding is reopened automatically.
    site.routes["/.env"] = (200, {}, b"DB_PASSWORD=hunter2hunter2\n")
    run(org, drain, a["id"])
    reopened = org.ok("GET", f"/findings/{env['id']}")
    assert reopened["status"] == "new" and any(e["event_type"] == "reopened" for e in reopened["timeline"])

    overview = org.ok("GET", "/dashboard/overview")
    assert overview["findings"]["critical"] + overview["findings"]["high"] >= 1 and overview["assets"]["internet_exposed"] == 1
    assert overview["attack_paths"]["active"] == 1 and overview["trend"][-1]["open_total"] >= 5


def test_risk_acceptance_requires_second_person_and_expires(org, drain, make_user, fake_dns, db_for):
    from datetime import UTC, datetime, timedelta

    scope(org, "domain", "example.test")
    a = org.ok("POST", "/assessments", json={"name": "dns", "kind": "dns_discovery", "targets": [{"kind": "domain", "value": "example.test"}]})
    run(org, drain, a["id"])
    finding = org.ok("GET", "/findings?q=SPF")["items"][0]
    analyst = make_user(org, "security_analyst")
    body = {"finding_id": finding["id"], "reason": "Domain sends no mail; SPF planned with migration in Q3.",
            "compensating_controls": "MX gateway rejects unauthenticated mail", "owner_user_id": org.user_id,
            "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat()}
    assert analyst.post("/risk/acceptances", json={**body, "expires_at": (datetime.now(UTC) + timedelta(days=900)).isoformat()}).status_code == 422
    acc = analyst.ok("POST", "/risk/acceptances", json=body)
    assert analyst.post(f"/risk/acceptances/{acc['id']}/decision", json={"approve": True}).status_code == 403  # no risk:approve
    manager = make_user(org, "vulnerability_manager")
    own = manager.ok("POST", "/risk/acceptances", json={**body, "finding_id": org.ok("GET", "/findings?q=DMARC")["items"][0]["id"]})
    assert manager.post(f"/risk/acceptances/{own['id']}/decision", json={"approve": True}).status_code == 403  # own request
    manager.ok("POST", f"/risk/acceptances/{acc['id']}/decision", json={"approve": True, "note": "ok"})
    assert org.ok("GET", f"/findings/{finding['id']}")["status"] == "accepted_risk"
    assert org.patch(f"/findings/{finding['id']}", json={"status": "accepted_risk"}).status_code in (200, 422)

    # Expiry returns the finding to triage.
    from app.models import RiskAcceptance
    from app.workers.queue import enqueue

    with db_for(org) as db:
        db.get(RiskAcceptance, acc["id"]).expires_at = datetime.now(UTC) - timedelta(minutes=1)
        enqueue(db, organization_id=org.org_id, job_type="risk.expire_acceptances")
    drain()
    assert org.ok("GET", f"/findings/{finding['id']}")["status"] == "triaged"
