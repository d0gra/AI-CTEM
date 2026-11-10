"""Scanner integrations: parsers, result import, real nmap/nuclei execution, OpenAPI analysis,
dependency analysis and threat-intel correlation."""

import json
import shutil

import httpx
import pytest

from app.integrations.intel import sources as intel
from app.integrations.scanners import parsers

TRIVY = {"ArtifactName": "registry.acme.test/shop/api:1.4.2", "ArtifactType": "container_image", "Results": [
    {"Target": "app/requirements.txt", "Class": "lang-pkgs", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2021-44228", "PkgName": "log4j-core", "InstalledVersion": "2.14.1", "FixedVersion": "2.15.0",
         "Severity": "CRITICAL", "Title": "Log4Shell", "Description": "JNDI lookup RCE", "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-44228",
         "CweIDs": ["CWE-502"]},
        {"VulnerabilityID": "CVE-2099-0001", "PkgName": "leftpad", "InstalledVersion": "1.0", "Severity": "LOW"}]},
    {"Target": "Dockerfile", "Class": "config", "Misconfigurations": [
        {"ID": "DS002", "Title": "Image user should not be 'root'", "Severity": "HIGH", "Status": "FAIL", "Resolution": "Add USER",
         "CauseMetadata": {"StartLine": 1}},
        {"ID": "DS026", "Title": "No HEALTHCHECK", "Severity": "LOW", "Status": "PASS"}]}]}
GRYPE = {"source": {"type": "directory", "target": "/src/shop"}, "matches": [{"vulnerability": {
    "id": "GHSA-jfh8-c2jp-5v3q", "severity": "Critical", "fix": {"versions": ["2.15.0"]}, "urls": ["https://github.com/advisories/GHSA-jfh8-c2jp-5v3q"]},
    "relatedVulnerabilities": [{"id": "CVE-2021-44228"}], "artifact": {"name": "log4j-core", "version": "2.14.1", "type": "java-archive"}}]}
SEMGREP = {"results": [{"check_id": "python.lang.security.audit.sqli.tainted-sql", "path": "app/db.py", "start": {"line": 42},
                        "extra": {"message": "User input in SQL", "severity": "ERROR", "metadata": {"cwe": ["CWE-89: SQL Injection"], "confidence": "HIGH"}}}]}
GITLEAKS = [{"RuleID": "aws-access-token", "Description": "AWS Access Key", "File": "deploy/.env", "StartLine": 3,
             "Secret": "AKIAIOSFODNN7EXAMPLE", "Match": "AWS_KEY=AKIAIOSFODNN7EXAMPLE", "Fingerprint": "abc:deploy/.env:aws-access-token:3"}]
CHECKOV = {"check_type": "terraform", "results": {"failed_checks": [{"check_id": "CKV_AWS_20", "check_name": "S3 Bucket has an ACL defined which allows public READ access",
                                                                       "file_path": "/s3.tf", "resource": "aws_s3_bucket.data", "file_line_range": [1, 9],
                                                                       "guideline": "https://docs.prismacloud.io/policy/ckv-aws-20"}]}}
ZAP = {"site": [{"@name": "https://shop.acme.test", "alerts": [{"pluginid": "40018", "alert": "SQL Injection", "riskcode": "3", "confidence": "2",
                                                               "desc": "<p>SQL injection may be possible.</p>", "solution": "<p>Use prepared statements.</p>",
                                                               "reference": "<p>https://owasp.org/sqli</p>", "cweid": "89",
                                                               "instances": [{"uri": "https://shop.acme.test/item?id=1", "method": "GET", "param": "id", "evidence": "syntax error"}]}]}]}
PROWLER = [
    {"status_code": "FAIL", "severity": "High", "finding_info": {"uid": "x", "title": "Storage account allows public blob access", "desc": "Public access"},
     "resources": [{"uid": "/subscriptions/1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acmedata", "name": "acmedata",
                    "type": "Microsoft.Storage/storageAccounts", "region": "westeurope"}],
     "cloud": {"provider": "azure", "account": {"uid": "sub-1"}}, "metadata": {"event_code": "storage_blob_public_access_level_is_disabled"},
     "remediation": {"desc": "Disable public access", "references": ["https://learn.microsoft.com/x"]}},
    {"status_code": "PASS", "severity": "Low", "finding_info": {"uid": "y", "title": "ok"}, "resources": [{"uid": "r2"}], "cloud": {"provider": "gcp"}},
]
NMAP_XML = b"""<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="8.8.4.4" addrtype="ipv4"/>
<hostnames><hostname name="db.acme.test"/></hostnames><ports>
<port protocol="tcp" portid="5432"><state state="open"/><service name="postgresql" product="PostgreSQL DB" version="14.2"/></port>
<port protocol="tcp" portid="11434"><state state="open"/><service name="http"/></port>
<port protocol="tcp" portid="81"><state state="closed"/></port></ports></host></nmaprun>"""


def test_parsers_normalise_each_format():
    trivy = list(parsers.parse_trivy(json.dumps(TRIVY).encode()))
    assert [f.rule_id for f in trivy] == ["CVE-2021-44228", "CVE-2099-0001", "DS002"]  # PASS results are not findings
    assert trivy[0].asset.type == "container_image" and trivy[0].cve == "CVE-2021-44228" and trivy[0].severity == "critical"
    assert "2.15.0" in trivy[0].remediation and trivy[2].domain == "iac"
    grype = list(parsers.parse_grype(json.dumps(GRYPE).encode()))
    assert grype[0].cve == "CVE-2021-44228" and grype[0].asset.identifier == "/src/shop"
    semgrep = list(parsers.parse_semgrep(json.dumps(SEMGREP).encode(), "git@acme/shop"))
    assert semgrep[0].cwe == "CWE-89" and semgrep[0].severity == "high" and semgrep[0].discriminator == "app/db.py:42"
    leaks = list(parsers.parse_gitleaks(json.dumps(GITLEAKS).encode(), "git@acme/shop"))
    assert "AKIA" not in json.dumps(leaks[0].evidence) and leaks[0].domain == "secrets"  # secret value is dropped
    assert list(parsers.parse_checkov(json.dumps(CHECKOV).encode(), "infra"))[0].rule_id == "CKV_AWS_20"
    zap = list(parsers.parse_zap(json.dumps(ZAP).encode()))
    assert zap[0].severity == "high" and zap[0].asset.identifier == "https://shop.acme.test" and "<p>" not in zap[0].description
    prowler = list(parsers.parse_prowler(json.dumps(PROWLER).encode()))
    assert len(prowler) == 1 and prowler[0].asset.type == "storage" and prowler[0].rule_id.startswith("prowler.azure.")
    hosts = parsers.parse_nmap_hosts(NMAP_XML)
    assert [(p.port, p.service) for p in hosts[0].ports] == [(5432, "postgresql"), (11434, "http")]


def test_wrong_format_is_rejected_not_silently_empty():
    with pytest.raises(parsers.ReportFormatError):
        list(parsers.parse_trivy(json.dumps(GRYPE).encode()))
    with pytest.raises(parsers.ReportFormatError):
        list(parsers.parse_semgrep(b"not json"))
    with pytest.raises(parsers.ReportFormatError):
        parsers.parse_nmap_hosts(b"<html></html>")
    with pytest.raises(parsers.ReportFormatError):  # XXE / entity expansion is refused by defusedxml
        parsers.parse_nmap_hosts(b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a SYSTEM "file:///etc/passwd">]><nmaprun>&a;</nmaprun>')


def upload(org, drain, fmt, payload, target=None, filename="report.json"):
    data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    r = org.post("/scanner-imports", data={"format": fmt, **({"target": target} if target else {})},
                 files={"file": (filename, data, "application/octet-stream")})
    assert r.status_code == 202, r.text
    drain()
    return org.ok("GET", f"/assessment-runs/{r.json()['id']}")


def kev_transport(request: httpx.Request) -> httpx.Response:
    if "known_exploited" in str(request.url):
        return httpx.Response(200, json={"catalogVersion": f"test-{id(request)}", "dateReleased": "2026-01-01T00:00:00Z", "vulnerabilities": [{
            "cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2", "vulnerabilityName": "Log4Shell RCE",
            "dateAdded": "2021-12-10", "shortDescription": "JNDI injection", "requiredAction": "Apply updates", "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known", "notes": "https://logging.apache.org/"}]})
    if "/epss" in str(request.url):
        cves = request.url.params["cve"].split(",")
        return httpx.Response(200, json={"data": [{"cve": c, "epss": "0.97", "percentile": "0.999", "date": "2026-01-01"}
                                                  for c in cves if c == "CVE-2021-44228"]})
    return httpx.Response(404)


def test_import_then_threat_intel_raises_priority(org, drain, monkeypatch):
    run = upload(org, drain, "trivy", TRIVY)
    assert run["status"] == "succeeded" and run["summary"]["findings_created"] == 3
    image = org.ok("GET", "/assets?type=container_image")["items"][0]
    assert image["identifier"] == "registry.acme.test/shop/api:1.4.2"
    log4j = org.ok("GET", "/findings?q=CVE-2021-44228")["items"][0]
    before = org.ok("GET", f"/findings/{log4j['id']}")
    assert before["vulnerability"]["kev"] is False and before["source"] == "import:trivy"

    # Same vulnerability reported by a second scanner on the same image is a separate observation
    # (different source) but resolves to the same catalogue entry.
    upload(org, drain, "grype", GRYPE, target="registry.acme.test/shop/api:1.4.2")
    assert org.ok("GET", "/intel/vulnerabilities?q=CVE-2021-44228")["items"][0]["affected_assets"] == 2

    monkeypatch.setattr(intel, "TRANSPORT", httpx.MockTransport(kev_transport))
    job = org.ok("POST", "/intel/sync?source=cisa_kev&source=epss")
    drain()
    result = org.ok("GET", f"/jobs/{job['job_id']}")
    assert result["state"] == "succeeded" and result["result"]["results"]["cisa_kev"]["records"] == 1, result
    after = org.ok("GET", f"/findings/{log4j['id']}")
    assert after["vulnerability"]["kev"] is True and after["vulnerability"]["epss_percentile"] == 0.999
    assert after["kev"] is True and after["risk_score"] > before["risk_score"]
    assert any(f["name"] == "kev" for f in after["risk"]["current"]["floors"])
    assert org.ok("GET", "/findings?kev=true")["total"] == 2
    assert org.ok("GET", "/intel/items?source=cisa_kev&q=Log4Shell")["items"][0]["source_url"].startswith("https://www.cisa.gov/")
    sources_state = {s["source"]: s for s in org.ok("GET", "/intel/sources")}
    assert sources_state["cisa_kev"]["last_success_at"] and sources_state["cisa_kev"]["last_error"] is None
    assert org.ok("GET", "/dashboard/overview")["findings"]["exploitable"] == 2


def test_intel_sync_failure_is_recorded_not_hidden(org, drain, monkeypatch):
    monkeypatch.setattr(intel, "TRANSPORT", httpx.MockTransport(lambda r: httpx.Response(503)))
    monkeypatch.setattr("time.sleep", lambda s: None)
    job = org.ok("POST", "/intel/sync?source=mitre_atlas")
    drain()
    drain()
    state = org.ok("GET", f"/jobs/{job['job_id']}")
    assert state["state"] in ("queued", "dead") and "All sources failed" in state["error"]
    assert next(s for s in org.ok("GET", "/intel/sources") if s["source"] == "mitre_atlas")["last_error"]


def test_import_rejects_wrong_format_and_oversize(org, drain, monkeypatch):
    run = upload(org, drain, "trivy", GRYPE)
    assert run["status"] == "failed" and "Not a Trivy JSON report" in run["error"]
    assert org.post("/scanner-imports", data={"format": "nessus"}, files={"file": ("x", b"{}")}).status_code == 422
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "max_upload_bytes", 10)
    assert org.post("/scanner-imports", data={"format": "trivy"}, files={"file": ("x", b"x" * 50)}).status_code == 422


def test_other_imports(org, drain):
    assert upload(org, drain, "nmap", NMAP_XML, filename="scan.xml")["summary"]["findings_created"] == 2
    services = org.ok("GET", "/findings?q=reachable&page_size=50")["items"]
    assert {(f["domain"], f["severity"]) for f in services} == {("network", "high"), ("ai_infra", "high")}
    assert upload(org, drain, "prowler", PROWLER)["summary"]["findings_created"] == 1
    storage_asset = org.ok("GET", "/assets?type=storage")["items"][0]
    assert storage_asset["name"] == "acmedata"
    assert upload(org, drain, "gitleaks", GITLEAKS, target="git@acme/shop")["status"] == "succeeded"
    leak = org.ok("GET", "/findings?domain=secrets")["items"][0]
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(org.ok("GET", f"/findings/{leak['id']}"))
    assert upload(org, drain, "gitleaks", GITLEAKS)["status"] == "failed"  # no target named


def osv_transport(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/v1/querybatch":
        queries = json.loads(request.content)["queries"]
        return httpx.Response(200, json={"results": [
            {"vulns": [{"id": "GHSA-test-lang-chain"}]} if q["package"].get("name") == "langchain" else {} for q in queries]})
    if request.url.path == "/v1/vulns/GHSA-test-lang-chain":
        return httpx.Response(200, json={
            "id": "GHSA-test-lang-chain", "aliases": ["CVE-2099-7777"], "summary": "Prompt template code execution",
            "details": "Arbitrary code execution through template loading.", "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-94"]},
            "affected": [{"package": {"ecosystem": "PyPI", "name": "langchain"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "0.9.9"}]}]}],
            "references": [{"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-test-lang-chain"}]})
    return httpx.Response(404)


def test_sbom_dependency_analysis(org, drain, monkeypatch):
    monkeypatch.setattr(intel, "TRANSPORT", httpx.MockTransport(osv_transport))
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"component": {"name": "support-bot"}}, "components": [
        {"name": "langchain", "version": "0.0.200", "purl": "pkg:pypi/langchain@0.0.200"},
        {"name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"},
        {"name": "internal-lib", "version": ""}]}
    run = upload(org, drain, "sbom", sbom)
    assert run["status"] == "succeeded", run
    assert run["summary"]["vulnerable_components"] == 1 and run["summary"]["skipped_no_version_or_ecosystem"] == 1
    finding = org.ok("GET", "/findings?domain=supply_chain")["items"][0]
    assert finding["vulnerability_external_id"] == "CVE-2099-7777" and finding["severity"] == "high"
    pkg = org.ok("GET", f"/assets/{finding['asset_id']}")
    assert pkg["type"] == "package" and pkg["attributes"]["ai_related"] is True
    assert org.ok("GET", "/dashboard/ai")["findings"]["vulnerable_ai_frameworks"] == 1
    spdx = {"spdxVersion": "SPDX-2.3", "name": "support-bot", "packages": [
        {"name": "langchain", "versionInfo": "0.0.200", "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:pypi/langchain@0.0.200"}]}]}
    assert parsers.parse_sbom(json.dumps(spdx).encode())[2][0].ecosystem == "PyPI"


@pytest.mark.skipif(shutil.which("nmap") is None, reason="nmap is not installed")
def test_nmap_executes_against_authorised_local_target(org, drain, allow_private, site):
    port = int(site.url.rsplit(":", 1)[1])
    org.ok("POST", "/scope", json={"kind": "cidr", "value": "127.0.0.1/32", "allow_active": True, "allow_private_network": True,
                                   "authorization_note": "Local test listener owned by the test suite"})
    assert org.post("/assessments", json={"name": "bad", "kind": "nmap_scan", "targets": [{"kind": "cidr", "value": "10.0.0.0/8"}]}).status_code == 403
    a = org.ok("POST", "/assessments", json={"name": "local ports", "kind": "nmap_scan", "config": {"ports": str(port), "service_detection": False},
                                             "targets": [{"kind": "cidr", "value": "127.0.0.1/32"}]})
    run_ = org.ok("POST", f"/assessments/{a['id']}/run", json={})
    drain()
    run_ = org.ok("GET", f"/assessment-runs/{run_['id']}")
    assert run_["status"] == "succeeded", run_
    assert "Nmap" in run_["summary"]["tool_version"]
    service = org.ok("GET", "/assets?type=network_service")["items"][0]
    assert service["identifier"] == f"127.0.0.1:{port}/tcp" and service["exposure"] == "internal"


@pytest.mark.skipif(shutil.which("nuclei") is None, reason="nuclei is not installed")
def test_nuclei_executes_with_a_local_template(org, drain, allow_private, site, tmp_path):
    site.routes["/"] = (200, {"Content-Type": "text/html"}, b"<html>acme-debug-console build 77</html>")
    template = tmp_path / "debug-console.yaml"
    template.write_text("""id: acme-debug-console
info:
  name: Acme debug console exposed
  author: ctem-tests
  severity: high
  description: The debug console is reachable.
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "acme-debug-console"
""")
    org.ok("POST", "/scope", json={"kind": "url", "value": site.url, "allow_active": True, "allow_private_network": True,
                                   "authorization_note": "Local test listener owned by the test suite"})
    a = org.ok("POST", "/assessments", json={"name": "nuclei local", "kind": "nuclei_scan", "targets": [{"kind": "url", "value": site.url}],
                                             "config": {"templates": str(template), "severities": ["high"], "exclude_tags": []}})
    run_ = org.ok("POST", f"/assessments/{a['id']}/run", json={})
    drain()
    run_ = org.ok("GET", f"/assessment-runs/{run_['id']}")
    assert run_["status"] == "succeeded", run_
    finding = org.ok("GET", "/findings?q=debug console")["items"][0]
    assert finding["rule_id"] == "acme-debug-console" and finding["severity"] == "high" and finding["source"] == "nuclei_scan"


OPENAPI = {"openapi": "3.0.3", "info": {"title": "Shop API", "version": "2.1"}, "servers": [{"url": "/api"}],
           "components": {"securitySchemes": {"key": {"type": "apiKey", "in": "query", "name": "api_key"}}},
           "security": [{"key": []}],
           "paths": {
               "/v1/orders": {"get": {"operationId": "listOrders", "responses": {"200": {"description": "ok"}}}},
               "/v2/profile": {"get": {"operationId": "profile", "responses": {"200": {"description": "ok"}}}},
               "/v1/orders/{order_id}": {"get": {"security": [], "parameters": [{"name": "order_id", "in": "path", "required": True}],
                                                 "responses": {"200": {"description": "ok"}}}},
               "/admin/users": {"delete": {"security": [], "responses": {"204": {"description": "gone"}}}},
               "/v1/legacy": {"get": {"deprecated": True, "responses": {"200": {"description": "ok"}}}},
               "/v1/login": {"post": {"security": [], "requestBody": {"content": {"application/json": {"schema": {"type": "object", "additionalProperties": True}}}},
                                      "responses": {"200": {"description": "ok"}}}}}}


def test_openapi_analysis_static_and_safe_probe(org, drain, allow_private, site):
    site.routes["/openapi.json"] = (200, {"Content-Type": "application/json"}, json.dumps(OPENAPI).encode())
    site.routes["/api/v1/orders"] = (200, {"Content-Type": "application/json"}, b'[{"id": 1, "total": 20}]')  # auth not enforced
    site.routes["/api/v2/profile"] = (401, {}, b"")
    org.ok("POST", "/scope", json={"kind": "url", "value": site.url, "allow_active": True, "allow_private_network": True,
                                   "authorization_note": "Local test listener owned by the test suite"})
    a = org.ok("POST", "/assessments", json={"name": "Shop API", "kind": "openapi_analysis", "config": {"probe_unauthenticated": True},
                                             "targets": [{"kind": "url", "value": f"{site.url}/openapi.json"}]})
    run_ = org.ok("POST", f"/assessments/{a['id']}/run", json={})
    drain()
    assert org.ok("GET", f"/assessment-runs/{run_['id']}")["status"] == "succeeded"
    rules = {}
    for f in org.ok("GET", "/findings?domain=api&page_size=100")["items"]:
        rules.setdefault(f["rule_id"], []).append(f)
    assert rules["api.auth.not_enforced"][0]["confidence"] == "confirmed" and "GET /v1/orders" in rules["api.auth.not_enforced"][0]["title"]
    assert len(rules["api.auth.not_enforced"]) == 1  # /v2/profile correctly returned 401
    assert rules["api.auth.missing"][0]["severity"] in ("high", "medium") and len(rules["api.auth.missing"]) == 2
    assert rules["api.bola.unauthenticated_object"][0]["confidence"] == "tentative"
    assert {"api.auth.key_in_query", "api.deprecated_operation", "api.mass_assignment.open_schema", "api.rate_limit.undeclared",
            "api.multiple_versions"} <= set(rules)
    assert org.ok("GET", "/assets?type=api_endpoint")["total"] == 6
    # Only GET requests were sent, and never to state-changing or parameterised operations.
    assert {m for m, *_ in site.requests} == {"GET"}
    assert not any("/admin" in p or "login" in p for _, p, *_ in site.requests)
