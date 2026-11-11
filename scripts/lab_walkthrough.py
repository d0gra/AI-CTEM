#!/usr/bin/env python3
"""Drive the platform against the local lab (scripts/lab.py) through the public API.

Prerequisites: API, worker (both with CTEM_ALLOW_PRIVATE_TARGETS=true), frontend and the lab are
running, an account exists, and http://127.0.0.1:8808 is in authorized scope (active testing,
private network). Credentials are read from CTEM_EMAIL / CTEM_PASSWORD.

    CTEM_EMAIL=... CTEM_PASSWORD=... python3 scripts/lab_walkthrough.py [http://localhost:3000]
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000").rstrip("/") + "/api/v1"
LAB = "http://127.0.0.1:8808"
TOKEN = ""


def call(method, path, body=None):
    request = urllib.request.Request(BASE + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Content-Type": "application/json", **({"Authorization": f"Bearer {TOKEN}"} if TOKEN else {})})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            text = response.read()
            return json.loads(text) if text else None
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode()
        if exc.code == 409:
            print(f"  (already exists: {method} {path})")
            return None
        raise SystemExit(f"{method} {path} -> {exc.code}: {detail}") from exc


def wait_for_run(run_id, label):
    for _ in range(90):
        run = call("GET", f"/assessment-runs/{run_id}")
        if run["status"] not in ("queued", "running"):
            summary = run["summary"] or {}
            print(f"  {label}: {run['status']}" + (f" - {run['error']}" if run["error"] else f" ({summary.get('findings_created', 0)} new findings, {summary.get('assets_created', 0)} new assets)"))
            return run
        time.sleep(1)
    raise SystemExit(f"{label}: timed out waiting for the worker; is it running?")


def assess(name, kind, targets=(), config=None):
    created = call("POST", "/assessments", {"name": name, "kind": kind, "config": config or {}, "targets": [{"kind": k, "value": v} for k, v in targets]})
    if created is None:
        return None
    run = call("POST", f"/assessments/{created['id']}/run", {})
    return wait_for_run(run["id"], name)


def main():
    global TOKEN
    TOKEN = call("POST", "/auth/login", {"email": os.environ["CTEM_EMAIL"], "password": os.environ["CTEM_PASSWORD"]})["access_token"]
    print("1. Exposure, API, MCP and inference-endpoint assessments")
    assess("Lab portal exposure", "http_exposure", [("url", LAB)])
    assess("Lab Shop API", "openapi_analysis", [("url", f"{LAB}/openapi.json")], {"probe_unauthenticated": True})
    assess("Lab MCP server", "mcp_probe", [("url", f"{LAB}/mcp")])
    assess("Lab inference endpoint", "ai_endpoint_probe", [("url", LAB)])

    print("2. Classification, crown-jewel asset and relationships")
    site = call("GET", "/assets?type=website")["items"][0]
    call("PATCH", f"/assets/{site['id']}", {"exposure": "internet", "criticality": "high", "environment": "production"})
    db = call("POST", "/assets", {"type": "database", "identifier": "postgres://orders-db.lab.internal/orders", "name": "Orders database",
                                  "criticality": "critical", "data_sensitivity": "restricted", "exposure": "private", "environment": "production"})
    if db:
        call("POST", "/asset-relationships", {"source_asset_id": site["id"], "target_asset_id": db["id"], "type": "CONNECTS_TO", "note": "Application connection string"})

    print("3. AI agent with excessive permissions, reading an attacker-writable inbox")
    agent = call("POST", "/ai/assets", {"type": "ai_agent", "identifier": "agent://support-triage", "name": "Support triage agent", "environment": "production", "exposure": "internal", "provider": "anthropic"})
    if agent:
        call("PATCH", f"/ai/assets/{agent['id']}", {"autonomy_level": "autonomous", "human_approval_required": False, "persistent_memory": True, "processes_untrusted_input": True,
                                                   "tools": [{"name": "issue_refund", "description": "Refund a payment", "capabilities": ["payment"], "requires_approval": False},
                                                             {"name": "search_kb", "description": "Search the knowledge base", "capabilities": ["search"]}]})
        inbox = call("POST", "/assets", {"type": "data_source", "identifier": "mailto:support@lab.example", "name": "Public support inbox", "exposure": "internet"})
        payments = call("POST", "/assets", {"type": "api", "identifier": "https://payments.lab.internal/api", "name": "Payments API", "criticality": "critical",
                                            "data_sensitivity": "restricted", "exposure": "private"})
        call("POST", "/asset-relationships", {"source_asset_id": agent["id"], "target_asset_id": inbox["id"], "type": "RETRIEVES_FROM", "note": "Reads inbound tickets"})
        call("POST", "/asset-relationships", {"source_asset_id": agent["id"], "target_asset_id": payments["id"], "type": "INVOKES_TOOL", "note": "issue_refund tool"})
    assess("AI posture review", "ai_posture_review")

    print("4. AI red team against the lab model")
    llm = call("POST", "/integrations", {"connector": "llm", "name": "Lab billing assistant", "credentials": {"api_key": "lab-not-a-real-key"},
                                         "config": {"api_style": "openai_compatible", "base_url": f"{LAB}/v1", "model": "lab-llm-8b"}})
    if llm:
        rt = call("POST", "/ai-redteam/assessments", {"name": "Lab assistant red team", "integration_id": llm["id"], "request_budget": 60, "rate_limit_per_minute": 120,
                                                      "authorization_statement": "Local practice lab owned by the developer; synthetic target started from scripts/lab.py."})
        run = call("POST", f"/ai-redteam/assessments/{rt['id']}/run")
        wait_for_run(run["run_id"], "Lab assistant red team")

    print("5. Attack paths, policies, remediation task, report")
    call("POST", "/attack-paths/compute")
    call("POST", "/policies/evaluate")
    time.sleep(4)
    top = call("GET", "/findings?open_only=true&page_size=1")["items"][0]
    call("POST", "/remediation/tasks", {"finding_id": top["id"]})
    call("POST", "/reports", {"type": "executive", "format": "pdf"})
    overview = call("GET", "/dashboard/overview")
    print(json.dumps({"assets": overview["assets"]["total"], "open_findings": overview["findings"]["open"], "critical": overview["findings"]["critical"],
                      "attack_paths": overview["attack_paths"]["active"], "ai_assets": overview["ai"]["assets"]}, indent=2))


if __name__ == "__main__":
    main()
