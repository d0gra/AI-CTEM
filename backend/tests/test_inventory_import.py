"""`ctem discover` inventories uploaded through the CI endpoint (format=ctem), end to end with the real CLI."""

import json
import sys
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

from app.integrations.intel import sources as intel
from tests.test_scanners import osv_transport

CLI = Path(__file__).resolve().parents[2] / "cli"
sys.path[:0] = [str(CLI / "src"), str(CLI / "tests")]

from conftest import FAKE_OPENAI_KEY, build_repo  # noqa: E402  (the CLI's fixture repository)
from ctem_cli import scan  # noqa: E402

REPO = "github.com/acme/support-bot"


def test_cli_inventory_upload(app, org, tmp_path, monkeypatch, drain):
    monkeypatch.setattr(intel, "TRANSPORT", httpx.MockTransport(osv_transport))  # langchain 0.0.200 is "vulnerable" in the stand-in
    report = scan.run(build_repo(tmp_path / "support-bot"))
    body = json.dumps(report)
    assert FAKE_OPENAI_KEY not in body

    token = org.ok("POST", "/ci/tokens", json={"name": "cli", "expires_in_days": 30})["token"]
    http = TestClient(app)
    r = http.post("/api/v1/ci/ingest", params={"format": "ctem", "repository": REPO, "commit": "4f2a9c1", "fail_on": "critical",
                                                 "exit_code": "true"}, content=body, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 412, r.text  # the committed provider key is critical, so the gate fails
    result = r.json()
    assert result["status"] == "succeeded" and result["findings_new"] >= 15

    assets = {(a["type"], a["identifier"]): a for a in org.ok("GET", "/assets", params={"page_size": 200})["items"]}
    assert ("repository", REPO) in assets and ("package", "pkg:pypi/openai@1.40.0") in assets
    for key in [("ai_provider", f"openai@{REPO}"), ("rag_application", f"app@{REPO}"), ("ai_agent", f"agent:{REPO}:src/agent.py"),
                ("mcp_server", "http://crm-mcp.acme.test/mcp"), ("ai_model", f"{REPO}/models/classifier.pkl"),
                ("llm_endpoint", "http://gpu-box.internal:11434"), ("container_image", "ollama/ollama")]:
        assert key in assets, key

    ai = {a["identifier"] for a in org.ok("GET", "/ai/assets", params={"page_size": 200})["items"]}
    assert f"agent:{REPO}:src/agent.py" in ai and f"app@{REPO}" in ai
    agent = org.ok("GET", f"/ai/assets/{assets[('ai_agent', f'agent:{REPO}:src/agent.py')]['id']}")
    assert {t["name"] for t in agent["agent"]["tools"]} >= {"refund_order", "search_docs"}
    mcp = org.ok("GET", f"/ai/assets/{assets[('mcp_server', 'http://crm-mcp.acme.test/mcp')]['id']}")["mcp"]
    assert mcp["transport"] == "streamable_http" and mcp["auth_type"] == "none"

    findings = org.ok("GET", "/findings", params={"source": "import:ctem", "page_size": 200})["items"]
    found = {f["rule_id"] for f in findings}
    assert {"ai.secret.openai_project_key", "mcp.config.insecure_transport", "ai.model.pickle_code_execution",
            "ai.agent.high_impact_tools_without_approval"} <= found
    assert any(f["vulnerability_external_id"] for f in findings)  # OSV lookup by the platform, from the package list

    usage = org.ok("GET", "/ai/integrations", params={"page_size": 200})["items"]
    assert any(u["provider"] == "openai" and u["detection_method"] == "dependency" for u in usage)

    # The AI posture review picks up the uploaded agent and its tools.
    drain()
    agent_findings = {f["rule_id"] for f in org.ok("GET", "/findings", params={"asset_id": agent["id"], "page_size": 50})["items"]}
    assert "ai.agent.excessive_agency" in agent_findings, agent_findings

    # A second upload of the same inventory does not duplicate anything.
    again = http.post("/api/v1/ci/ingest", params={"format": "ctem", "repository": REPO}, content=body, headers={"Authorization": f"Bearer {token}"})
    assert again.status_code == 200 and again.json()["findings_new"] == 0


def test_inventory_validation(app, org):
    token = org.ok("POST", "/ci/tokens", json={"name": "cli", "expires_in_days": 30})["token"]
    http = TestClient(app)
    headers = {"Authorization": f"Bearer {token}"}
    bad = http.post("/api/v1/ci/ingest", params={"format": "ctem", "exit_code": "true"}, content=b'{"schema": "other"}', headers=headers)
    assert bad.status_code == 422 and "ctem inventory" in bad.json()["error"]
    weird = {"schema": "ctem-inventory/1", "assets": [
        {"type": "repository", "identifier": "github.com/acme/x", "name": "x", "ref": "repository:github.com/acme/x"},
        {"type": "not_a_type", "identifier": "zzz"}, {"type": "ai_provider", "identifier": "openai@github.com/acme/x", "ai": {"approval_status": "approved"}}],
        "relationships": [{"source": "repository:github.com/acme/x", "target": "nowhere", "type": "DEPENDS_ON"}],
        "findings": [{"rule_id": "x", "title": "bad severity", "severity": "catastrophic", "domain": "secrets", "asset": "repository:github.com/acme/x"}]}
    ok = http.post("/api/v1/ci/ingest", params={"format": "ctem"}, content=json.dumps(weird), headers=headers)
    assert ok.status_code == 200 and ok.json()["findings_new"] == 0
    provider = next(a for a in org.ok("GET", "/ai/assets", params={"page_size": 50})["items"] if a["identifier"] == "openai@github.com/acme/x")
    assert provider["approval_status"] == "unknown"  # approval cannot be set by an upload
