"""CI/CD ingestion: scoped tokens, raw and multipart uploads, the build gate, and tenant isolation."""

import json

from fastapi.testclient import TestClient

from tests.test_scanners import GITLEAKS, TRIVY


def _token(org, name="github-actions"):
    return org.ok("POST", "/ci/tokens", json={"name": name, "expires_in_days": 30})


def test_ci_token_can_only_ingest(app, org):
    created = _token(org)
    raw = created["token"]
    assert raw.startswith("ctem_ci_") and created["prefix"] == raw[:16]
    assert raw not in json.dumps(org.ok("GET", "/ci/tokens"))  # never shown again
    http = TestClient(app)
    ci = {"Authorization": f"Bearer {raw}"}
    for path in ("/api/v1/assets", "/api/v1/findings", "/api/v1/auth/me", "/api/v1/imports"):
        assert http.get(path, headers=ci).status_code == 401, path
    assert http.post("/api/v1/ci/ingest?format=trivy", content=b"{}", headers={"Authorization": "Bearer ctem_ci_forged"}).status_code == 401
    assert http.post("/api/v1/ci/ingest?format=trivy", content=b"{}", headers={"Authorization": f"Bearer {org.token}"}).status_code == 401


def test_pipeline_upload_with_gate(app, org, make_org):
    raw = _token(org)["token"]
    http = TestClient(app)
    ci = {"Authorization": f"Bearer {raw}", "Content-Type": "application/json"}
    params = {"format": "trivy", "repository": "github.com/acme/shop", "branch": "main", "commit": "4f2a9c1",
              "pipeline_url": "https://github.com/acme/shop/actions/runs/42", "provider": "github_actions", "fail_on": "high"}
    r = http.post("/api/v1/ci/ingest", params={**params, "exit_code": "true"}, content=json.dumps(TRIVY), headers=ci)
    assert r.status_code == 412, r.text  # a critical finding fails the build
    body = r.json()
    assert body["status"] == "succeeded" and body["findings_new"] == 3
    assert body["gate"]["passed"] is False and body["gate"]["blocking"][0]["severity"] == "critical"
    assert body["gate"]["open_by_severity"] == {"critical": 1, "low": 1, "high": 1} and body["ci"]["commit"] == "4f2a9c1"

    # Accepting the risk on the blocking findings lets the next build pass; re-uploads do not duplicate findings.
    for b in body["gate"]["blocking"]:
        org.ok("PATCH", f"/findings/{b['id']}", json={"status": "false_positive", "note": "Not reachable in our build; verified by AppSec"})
    again = http.post("/api/v1/ci/ingest", params={**params, "commit": "77aa001", "exit_code": "true"}, content=json.dumps(TRIVY), headers=ci)
    assert again.status_code == 200 and again.json()["gate"]["passed"] and again.json()["findings_new"] == 0
    assert again.json()["gate"]["suppressed"] == 2

    # Multipart upload works too, and gitleaks without a target uses the repository name.
    r = http.post("/api/v1/ci/ingest", params={"format": "gitleaks", "repository": "github.com/acme/shop"},
                  files={"file": ("gitleaks.json", json.dumps(GITLEAKS), "application/json")}, headers={"Authorization": f"Bearer {raw}"})
    assert r.status_code == 200 and r.json()["gate"]["threshold"] == "none" and r.json()["findings_new"] == 1

    repo = org.ok("GET", "/assets", params={"type": "repository"})["items"][0]
    assert repo["identifier"] == "github.com/acme/shop"
    image = org.ok("GET", "/assets", params={"type": "container_image"})["items"][0]
    assert org.ok("GET", f"/assets/{image['id']}")["attributes"]["last_ci_build"]["commit"] == "77aa001"

    history = org.ok("GET", "/imports", params={"source": "ci"})
    assert history["total"] == 3 and history["items"][0]["ci"]["token_name"] == "github-actions"
    assert org.ok("GET", "/assessments")["total"] == 0  # uploads are not listed as assessments
    # Bad reports fail clearly.
    bad = http.post("/api/v1/ci/ingest", params={"format": "semgrep", "repository": "x", "exit_code": "true"}, content=b'{"nope": 1}', headers=ci)
    assert bad.status_code == 422 and "Not a Semgrep JSON report" in bad.json()["error"]
    assert http.post("/api/v1/ci/ingest", params={"format": "nessus"}, content=b"{}", headers=ci).status_code == 422

    # Another organization never sees these uploads, and a revoked token stops working.
    other = make_org("Other")
    assert other.ok("GET", "/imports")["total"] == 0
    assert http.get(f"/api/v1/ci/uploads/{body['id']}", headers={"Authorization": f"Bearer {_token(other)['token']}"}).status_code == 404
    token_id = org.ok("GET", "/ci/tokens")[0]["id"]
    org.ok("DELETE", f"/ci/tokens/{token_id}", expected=204)
    assert http.post("/api/v1/ci/ingest", params=params, content=json.dumps(TRIVY), headers=ci).status_code == 401


def test_manual_upload_appears_in_history(org, drain):
    r = org.post("/scanner-imports", data={"format": "trivy"}, files={"file": ("trivy.json", json.dumps(TRIVY).encode(), "application/json")})
    assert r.status_code == 202
    drain()
    item = org.ok("GET", "/imports", params={"source": "manual"})["items"][0]
    assert item["status"] == "succeeded" and item["ci"] is None and item["filename"] == "trivy.json"
