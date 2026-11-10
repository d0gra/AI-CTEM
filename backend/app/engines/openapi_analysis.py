"""API security analysis from an OpenAPI / Swagger description.

The static pass inventories endpoints and flags design-level weaknesses (missing
authentication, credentials in URLs, deprecated operations, object identifiers without
authorization, permissive request schemas). The optional active pass sends one unauthenticated
GET per parameter-free operation that declares authentication, to detect endpoints that answer
without credentials. Only GET is used; no state-changing request is ever sent.
"""

import json
import re
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, Field

from app.core.net import safe_fetch
from app.domains.assessments.service import EngineContext, EngineSpec, register
from app.domains.assets.service import AssetSpec
from app.domains.findings.service import EvidenceInput, FindingInput
from app.workers.queue import PermanentJobError

METHODS = ("get", "put", "post", "delete", "patch", "head", "options")
SENSITIVE_PATH = re.compile(r"/(admin|internal|debug|actuator|management|private|backup|config|console|metrics|swagger|graphql)(/|$)", re.I)
ID_PARAM = re.compile(r"(^id$|_id$|Id$|uuid|guid)", re.I)
VERSION = re.compile(r"/v(\d+)(?:[./]|$)")


class OpenApiConfig(BaseModel):
    probe_unauthenticated: bool = Field(default=False, description="Send unauthenticated GET requests to operations that declare authentication")
    max_probes: int = Field(default=25, ge=1, le=100)


def load_spec(body: bytes) -> dict:
    try:
        doc = json.loads(body)
    except ValueError:
        try:
            doc = yaml.safe_load(body)
        except yaml.YAMLError as exc:
            raise PermanentJobError(f"The document is neither JSON nor YAML: {exc}") from exc
    if not isinstance(doc, dict) or not ("openapi" in doc or "swagger" in doc) or not isinstance(doc.get("paths"), dict):
        raise PermanentJobError("The document is not an OpenAPI 3.x or Swagger 2.0 description")
    return doc


def _security_schemes(doc: dict) -> dict:
    return (doc.get("components") or {}).get("securitySchemes") or doc.get("securityDefinitions") or {}


def _servers(doc: dict, spec_url: str) -> list[str]:
    parts = urlsplit(spec_url)
    origin = f"{parts.scheme}://{parts.netloc}"
    if "swagger" in doc:
        schemes = doc.get("schemes") or [parts.scheme]
        return [f"{s}://{doc.get('host') or parts.netloc}{doc.get('basePath', '')}".rstrip("/") for s in schemes]
    out = []
    for server in doc.get("servers") or [{"url": "/"}]:
        url = str(server.get("url", "/"))
        out.append((origin + url if url.startswith("/") else url).rstrip("/"))
    return out or [origin]


def _resolve(doc: dict, node):
    for _ in range(5):
        if isinstance(node, dict) and "$ref" in node and str(node["$ref"]).startswith("#/"):
            target = doc
            for part in node["$ref"][2:].split("/"):
                target = target.get(part, {}) if isinstance(target, dict) else {}
            node = target
        else:
            break
    return node if isinstance(node, dict) else {}


def analyse(ctx: EngineContext, spec_url: str, doc: dict, allow_private: bool) -> None:
    config: OpenApiConfig = ctx.config  # type: ignore[assignment]
    info = doc.get("info") or {}
    servers = _servers(doc, spec_url)
    schemes = _security_schemes(doc)
    global_security = doc.get("security")
    api = ctx.asset(AssetSpec(
        type="api", identifier=spec_url, name=info.get("title") or f"API at {urlsplit(spec_url).netloc}",
        attributes={"version": info.get("version"), "spec_version": doc.get("openapi") or doc.get("swagger"),
                    "servers": servers, "security_schemes": sorted(schemes), "spec_url": spec_url}))
    common = {"asset": api, "source": ctx.source, "domain": "api"}

    def ev(summary: str, content: dict) -> list[EvidenceInput]:
        return [EvidenceInput("config", summary, {"spec_url": spec_url, **content})]

    for server in servers:
        if server.startswith("http://") and not re.match(r"http://(localhost|127\.|\[::1\])", server):
            ctx.finding(FindingInput(**common, rule_id="api.server.plaintext", discriminator=server, severity="medium",
                                     confidence="confirmed", cwe="CWE-319", title=f"API server is declared over plaintext HTTP: {server}",
                                     description="The specification advertises a non-TLS server URL.",
                                     remediation="Serve the API exclusively over HTTPS.", evidence=ev("servers", {"servers": servers})))
    for name, scheme in schemes.items():
        if scheme.get("type") == "apiKey" and scheme.get("in") == "query":
            ctx.finding(FindingInput(**common, rule_id="api.auth.key_in_query", discriminator=name, severity="medium",
                                     confidence="confirmed", cwe="CWE-598", title=f"API key '{scheme.get('name')}' is sent in the query string",
                                     description="Credentials in URLs are recorded in logs, browser history and intermediaries.",
                                     remediation="Send API keys in a request header.", evidence=ev("securitySchemes", {name: scheme})))
        if scheme.get("type") == "http" and str(scheme.get("scheme", "")).lower() == "basic":
            ctx.finding(FindingInput(**common, rule_id="api.auth.basic", discriminator=name, severity="low", confidence="confirmed",
                                     cwe="CWE-522", title="API uses HTTP Basic authentication",
                                     description="Basic authentication sends reusable credentials on every request.",
                                     remediation="Prefer short-lived tokens (OAuth 2.0 / OIDC).", evidence=ev("securitySchemes", {name: scheme})))
    versions: set[str] = set()
    unauthenticated, probes = [], []
    operations = 0
    for path, item in doc["paths"].items():
        if not isinstance(item, dict):
            continue
        versions.update(VERSION.findall(path))
        for method in METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            operations += 1
            label = f"{method.upper()} {path}"
            security = op.get("security", global_security)
            requires_auth = bool(security) and any(s for s in security)
            params = [_resolve(doc, p) for p in [*(item.get("parameters") or []), *(op.get("parameters") or [])]]
            path_params = [p.get("name", "") for p in params if p.get("in") == "path"]
            endpoint = ctx.asset(AssetSpec(
                type="api_endpoint", identifier=f"{method.upper()} {servers[0]}{path}", name=label,
                attributes={"operation_id": op.get("operationId"), "requires_auth": requires_auth, "deprecated": bool(op.get("deprecated")),
                            "tags": op.get("tags"), "path_parameters": path_params}))
            ctx.link(api, endpoint, "CONTAINS")
            op_ev = ev(label, {"operation": {k: op.get(k) for k in ("operationId", "security", "deprecated", "tags")}})
            if not requires_auth:
                unauthenticated.append(label)
                sensitive = bool(SENSITIVE_PATH.search(path))
                writes = method in ("post", "put", "patch", "delete")
                if sensitive or writes:
                    ctx.finding(FindingInput(
                        **common, rule_id="api.auth.missing", discriminator=label, cwe="CWE-306",
                        severity="high" if sensitive else "medium", confidence="firm",
                        title=f"No authentication is declared for {label}",
                        description="The operation has no security requirement"
                        + (" and its path indicates an administrative or internal function." if sensitive else " and it modifies state."),
                        technical_impact="If the implementation matches the specification, anyone can invoke this operation.",
                        remediation="Declare and enforce a security requirement for the operation; verify the implementation rejects anonymous calls.",
                        evidence=op_ev))
            elif method == "get" and not path_params and "{" not in path:
                probes.append((label, f"{servers[0]}{path}"))
            if requires_auth is False and any(ID_PARAM.search(p) for p in path_params) and method == "get":
                ctx.finding(FindingInput(
                    **common, rule_id="api.bola.unauthenticated_object", discriminator=label, severity="high", confidence="tentative",
                    cwe="CWE-639", title=f"Object identifier is accepted without authentication: {label}",
                    description="The operation addresses an object by identifier and declares no security requirement, a precondition for broken object-level authorization (OWASP API1:2023).",
                    remediation="Authenticate the caller and verify ownership of the referenced object on every request.",
                    references=["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"], evidence=op_ev))
            if op.get("deprecated"):
                ctx.finding(FindingInput(**common, rule_id="api.deprecated_operation", discriminator=label, severity="low",
                                         confidence="confirmed", title=f"Deprecated operation is still published: {label}",
                                         description="Deprecated operations frequently miss later security controls (OWASP API9:2023).",
                                         remediation="Remove the operation or schedule its retirement.", evidence=op_ev))
            if SENSITIVE_PATH.search(path) and requires_auth:
                endpoint.tags = sorted(set(endpoint.tags) | {"sensitive-endpoint"})
            if method in ("post", "put", "patch"):
                content = (_resolve(doc, op.get("requestBody")).get("content") or {})
                schema = _resolve(doc, (content.get("application/json") or {}).get("schema"))
                if schema.get("type") == "object" and schema.get("additionalProperties") is True:
                    ctx.finding(FindingInput(
                        **common, rule_id="api.mass_assignment.open_schema", discriminator=label, severity="low", confidence="tentative",
                        cwe="CWE-915", title=f"Request body accepts arbitrary properties: {label}",
                        description="additionalProperties: true allows clients to submit fields the API did not intend to accept (mass assignment, OWASP API3:2023).",
                        remediation="Set additionalProperties: false and bind only allow-listed fields.", evidence=op_ev))
            if "429" not in (op.get("responses") or {}) and method in ("post",) and re.search(r"login|token|auth|password|otp|reset", path, re.I):
                ctx.finding(FindingInput(
                    **common, rule_id="api.rate_limit.undeclared", discriminator=label, severity="low", confidence="tentative", cwe="CWE-307",
                    title=f"Authentication endpoint declares no rate-limit response: {label}",
                    description="The operation does not document a 429 response; confirm that brute-force protection exists (OWASP API4:2023).",
                    remediation="Enforce and document rate limiting on authentication endpoints.", evidence=op_ev))
    if len(versions) > 1:
        ctx.finding(FindingInput(**common, rule_id="api.multiple_versions", severity="info", confidence="confirmed",
                                 title=f"Multiple API versions are published side by side: {', '.join('v' + v for v in sorted(versions))}",
                                 description="Older versions should be inventoried and retired on a schedule (OWASP API9:2023).",
                                 remediation="Confirm each published version is still required and equally protected.",
                                 evidence=ev("paths", {"versions": sorted(versions)})))
    api.attributes = {**api.attributes, "operations": operations, "unauthenticated_operations": len(unauthenticated)}
    ctx.stats["operations"] = ctx.stats.get("operations", 0) + operations

    if config.probe_unauthenticated:
        for label, url in probes[: config.max_probes]:
            ctx.checkpoint()
            ctx.scope(url, active=True)
            ctx.stats["requests"] += 1
            try:
                r = safe_fetch("GET", url, allow_private=allow_private, verify_tls=False, max_redirects=0, max_bytes=64 * 1024)
            except Exception as exc:
                ctx.skip(url, f"{type(exc).__name__}: {exc}"[:200])
                continue
            if r.status_code == 200 and r.body.strip():
                ctx.finding(FindingInput(
                    **common, rule_id="api.auth.not_enforced", discriminator=label, severity="high", confidence="confirmed", cwe="CWE-306",
                    title=f"Authentication is declared but not enforced: {label}",
                    description="The specification requires credentials for this operation, but an anonymous request returned HTTP 200 with a body.",
                    technical_impact="Data or functionality intended for authenticated users is available to anyone.",
                    remediation="Enforce authentication in the handler or gateway for this route.", reproduction=f"curl -i {url}",
                    references=["https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"],
                    evidence=[EvidenceInput("http_exchange", f"GET {url} -> HTTP {r.status_code}", {
                        "request": {"method": "GET", "url": url, "headers": {}},
                        "response": {"status": r.status_code, "content_type": r.headers.get("content-type"), "body_excerpt": r.text()[:400]}})]))
    ctx.mark_complete(api)


def run(ctx: EngineContext) -> None:
    config: OpenApiConfig = ctx.config  # type: ignore[assignment]
    for target in ctx.targets:
        url = target.value
        decision = ctx.scope(url, active=True)
        if ctx.dry_run:
            ctx.planned(f"GET {url} and analyse the OpenAPI description" + (
                f"; up to {config.max_probes} unauthenticated GET probes" if config.probe_unauthenticated else ""))
            continue
        ctx.stats["requests"] += 1
        result = safe_fetch("GET", url, allow_private=decision.allow_private, verify_tls=False, max_bytes=10 * 1024 * 1024)
        if result.status_code != 200:
            raise PermanentJobError(f"Fetching the specification returned HTTP {result.status_code}")
        analyse(ctx, url, load_spec(result.body), decision.allow_private)


register(EngineSpec(
    kind="openapi_analysis", name="API security analysis (OpenAPI)", module="web_api", run=run,
    description="Inventories API endpoints from an OpenAPI/Swagger document and flags missing authentication, "
                "credentials in URLs, deprecated operations and authorization design weaknesses. Optional read-only probes "
                "verify that declared authentication is enforced.",
    config_model=OpenApiConfig, target_kinds=("url",), active=True,
))
