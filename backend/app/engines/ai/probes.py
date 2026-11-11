"""Live, read-only probes of AI infrastructure: MCP servers and model inference endpoints.

Neither probe invokes a tool or generates text. The MCP probe performs the protocol handshake
and the three listing methods only; `tools/call` is never sent. The inference probe requests
model listings only.
"""

import json
from typing import Any

from pydantic import BaseModel

from app.core.net import FetchResult, is_public_ip, safe_fetch
from app.db.base import utcnow
from app.domains.assessments.service import EngineContext, EngineSpec, register
from app.domains.assets.service import AssetSpec
from app.domains.findings.service import EvidenceInput, FindingInput
from app.engines.ai import mcp_analysis
from app.models import AIAsset, MCPServer

MCP_PROTOCOL_VERSION = "2025-06-18"
ALLOWED_MCP_METHODS = ("initialize", "notifications/initialized", "tools/list", "resources/list", "prompts/list")


def _exposure(result: FetchResult) -> str:
    import ipaddress

    try:
        return "internet" if is_public_ip(ipaddress.ip_address(result.resolved_ip)) else "internal"
    except ValueError:
        return "unknown"


def _rpc_payload(result: FetchResult) -> dict | None:
    """Extract the JSON-RPC message from a JSON or SSE response body."""
    text = result.text()
    if "text/event-stream" in result.headers.get("content-type", ""):
        for line in text.splitlines():
            if line.startswith("data:"):
                try:
                    message = json.loads(line[5:].strip())
                except ValueError:
                    continue
                if isinstance(message, dict) and ("result" in message or "error" in message):
                    return message
        return None
    try:
        message = json.loads(text)
    except ValueError:
        return None
    return message if isinstance(message, dict) else None


class McpProbeConfig(BaseModel):
    pass


def run_mcp_probe(ctx: EngineContext) -> None:
    for target in ctx.targets:
        url = target.value
        decision = ctx.scope(url, active=True)
        if ctx.dry_run:
            ctx.planned(f"MCP handshake with {url}: initialize, tools/list, resources/list, prompts/list (no tool invocation)")
            continue
        session: dict[str, str] = {}
        counter = iter(range(1, 100))

        def call(method: str, params: dict | None = None, notify: bool = False, _url=url, _session=session, _dec=decision, _ids=counter) -> FetchResult:
            if method not in ALLOWED_MCP_METHODS:  # hard guard: this probe can never invoke a tool
                raise RuntimeError(f"MCP method {method} is not permitted in a probe")
            body: dict = {"jsonrpc": "2.0", "method": method}
            if params is not None:
                body["params"] = params
            if not notify:
                body["id"] = next(_ids)
            ctx.stats["requests"] += 1
            return safe_fetch("POST", _url, allow_private=_dec.allow_private, json_body=body, verify_tls=False, max_redirects=0,
                              max_bytes=2 * 1024 * 1024, headers={"Accept": "application/json, text/event-stream",
                                                                 "MCP-Protocol-Version": MCP_PROTOCOL_VERSION, **_session})

        init = call("initialize", {"protocolVersion": MCP_PROTOCOL_VERSION, "capabilities": {},
                                   "clientInfo": {"name": "ctem-mcp-probe", "version": "0.1"}})
        asset = ctx.asset(AssetSpec(type="mcp_server", identifier=url, name=f"MCP server {url.split('//', 1)[-1]}",
                                    exposure=_exposure(init), ai={"provider": "mcp"}))
        row = ctx.db.get(MCPServer, asset.id)
        if row is None:
            row = MCPServer(organization_id=asset.organization_id, asset_id=asset.id, transport="streamable_http")
            ctx.db.add(row)
        row.endpoint, row.uses_tls, row.last_probed_at = url, url.startswith("https://"), utcnow()
        ai = ctx.db.get(AIAsset, asset.id)
        common: dict[str, Any] = {"asset": asset, "source": ctx.source, "domain": "ai_mcp"}
        handshake = EvidenceInput("http_exchange", f"POST {url} initialize -> HTTP {init.status_code}", {
            "request": {"method": "POST", "url": url, "jsonrpc_method": "initialize", "authorization_header_sent": False},
            "response": {"status": init.status_code, "www_authenticate": init.headers.get("www-authenticate"),
                         "content_type": init.headers.get("content-type"), "body_excerpt": init.text()[:500]}})
        if not row.uses_tls:
            ctx.finding(FindingInput(**common, rule_id="mcp.transport.plaintext", severity="high", confidence="confirmed", cwe="CWE-319",
                                     title="MCP server accepts connections over plaintext HTTP",
                                     description="Tool calls, tool results and bearer tokens are exposed to network observers.",
                                     remediation="Serve MCP only over HTTPS.", evidence=[handshake]))
        message = _rpc_payload(init) if init.status_code == 200 else None
        if init.status_code in (401, 403):
            row.auth_type = "oauth" if "resource_metadata" in init.headers.get("www-authenticate", "") else "bearer"
            if ai:
                ai.auth_required = True
            ctx.stats["authenticated"] = ctx.stats.get("authenticated", 0) + 1
            ctx.mark_complete(asset)
            continue
        if message is None or "result" not in message:
            ctx.skip(url, f"No MCP initialize result (HTTP {init.status_code}); endpoint may not be an MCP server")
            continue
        row.auth_type = "none"
        if ai:
            ai.auth_required = False
        info = message["result"]
        row.server_info = {"serverInfo": info.get("serverInfo"), "protocolVersion": info.get("protocolVersion"),
                           "capabilities": sorted((info.get("capabilities") or {}).keys())}
        if init.headers.get("mcp-session-id"):
            session["Mcp-Session-Id"] = init.headers["mcp-session-id"]
        ctx.finding(FindingInput(
            **common, rule_id="mcp.auth.none", severity="critical" if asset.exposure == "internet" else "high", confidence="confirmed",
            cwe="CWE-306", owasp_llm="LLM06:2025", atlas_technique="AML.T0053",
            title="MCP server accepts unauthenticated clients",
            description="The initialize handshake succeeded without any credential. Any client that can reach the endpoint can list and invoke its tools.",
            technical_impact="Unauthenticated access to every tool and resource the server exposes.",
            remediation="Require OAuth 2.1 (per the MCP authorization specification) or, at minimum, a bearer token validated on every request.",
            reproduction=f"curl -s -X POST {url} -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' "
                         "-d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"" + MCP_PROTOCOL_VERSION
                         + "\",\"capabilities\":{},\"clientInfo\":{\"name\":\"probe\",\"version\":\"0\"}}}'",
            evidence=[handshake]))
        call("notifications/initialized", notify=True)
        listings: dict[str, list] = {}
        for method, key in (("tools/list", "tools"), ("resources/list", "resources"), ("prompts/list", "prompts")):
            ctx.checkpoint()
            response = call(method, {})
            payload = _rpc_payload(response) if response.status_code == 200 else None
            listings[key] = (payload or {}).get("result", {}).get(key) or [] if payload and "result" in payload else []
        tools = mcp_analysis.normalise_tools(listings["tools"])
        row.tools = tools
        ctx.stats["tools_listed"] = ctx.stats.get("tools_listed", 0) + len(tools)
        for raw in listings["tools"]:
            if not isinstance(raw, dict):
                continue
            indicators = mcp_analysis.poisoning_indicators(raw)
            if indicators:
                ctx.finding(FindingInput(
                    **common, rule_id="mcp.tool.poisoning_indicators", discriminator=str(raw.get("name")), severity="high",
                    confidence="firm" if any(i["indicator"] in ("instruction_override", "concealment", "exfiltration") for i in indicators) else "tentative",
                    owasp_llm="LLM01:2025", atlas_technique="AML.T0051.001",
                    title=f"MCP tool '{raw.get('name')}' metadata contains prompt-injection indicators",
                    description="Tool metadata is inserted into the model's context. The text below matches patterns used to redirect a model "
                                "(tool poisoning). Review the excerpts: indicators are evidence for review, not a verdict.",
                    technical_impact="A client that loads this tool may follow the embedded instructions with the user's privileges.",
                    remediation="Remove the server or pin a reviewed version; have clients display full tool descriptions and require approval.",
                    evidence=[EvidenceInput("config", f"tools/list entry '{raw.get('name')}'", {"tool": raw.get("name"), "indicators": indicators})]))
        dangerous = [t for t in tools if set(t["capabilities"]) & {"shell", "code_execution", "filesystem_write", "database_write", "payment", "iam_admin", "deploy"}]
        if dangerous:
            ctx.finding(FindingInput(
                **common, rule_id="mcp.tool.high_impact_unauthenticated", severity="critical", confidence="confirmed", owasp_llm="LLM06:2025",
                title=f"Unauthenticated MCP server exposes {len(dangerous)} high-impact tool(s)",
                description="Tools capable of executing commands, writing data or changing access are callable without authentication: "
                            + ", ".join(f"{t['name']} ({'/'.join(t['capabilities'])})" for t in dangerous[:8]) + ". Tools were listed, not invoked.",
                remediation="Require authentication and per-tool authorization; remove tools that are not needed.",
                evidence=[EvidenceInput("config", "tools/list response", {"tools": [{"name": t["name"], "capabilities": t["capabilities"]} for t in dangerous[:25]]})]))
        sensitive = [r.get("uri") for r in listings["resources"] if isinstance(r, dict) and str(r.get("uri", "")).startswith(("file://", "postgres://", "mysql://", "s3://"))]
        if sensitive:
            ctx.finding(FindingInput(**common, rule_id="mcp.resource.exposed", severity="high", confidence="confirmed", owasp_llm="LLM02:2025",
                                     title=f"Unauthenticated MCP server lists {len(sensitive)} file or data-store resource(s)",
                                     description="Resources backed by files or databases are enumerable without authentication. Resources were listed, not read.",
                                     remediation="Authenticate clients and scope resource roots to the minimum required.",
                                     evidence=[EvidenceInput("config", "resources/list response", {"uris": sensitive[:25]})]))
        ctx.mark_complete(asset)


class EndpointProbeConfig(BaseModel):
    pass


def run_endpoint_probe(ctx: EngineContext) -> None:
    for target in ctx.targets:
        base = target.value.rstrip("/")
        decision = ctx.scope(base, active=True)
        if ctx.dry_run:
            ctx.planned(f"GET {base}/v1/models and {base}/api/tags without credentials (model listing only)")
            continue
        observed: dict[str, FetchResult] = {}
        for path in ("/v1/models", "/api/tags", "/v2/models"):
            ctx.stats["requests"] += 1
            try:
                observed[path] = safe_fetch("GET", base + path, allow_private=decision.allow_private, verify_tls=False,
                                            max_redirects=0, max_bytes=512 * 1024)
            except Exception as exc:
                ctx.skip(base + path, f"{type(exc).__name__}: {exc}"[:200])
        if not observed:
            continue
        first = next(iter(observed.values()))
        models: list[str] = []
        kind, open_path = None, None
        for path, r in observed.items():
            if r.status_code != 200:
                continue
            try:
                doc = r.json()
            except ValueError:
                continue
            if path == "/v1/models" and isinstance(doc, dict) and isinstance(doc.get("data"), list):
                models, kind, open_path = [str(m.get("id")) for m in doc["data"] if isinstance(m, dict)], "openai_compatible", path
                break
            if path == "/api/tags" and isinstance(doc, dict) and isinstance(doc.get("models"), list):
                models, kind, open_path = [str(m.get("name")) for m in doc["models"] if isinstance(m, dict)], "ollama", path
                break
        requires_auth = any(r.status_code in (401, 403) for r in observed.values())
        if kind is None and not requires_auth:
            ctx.skip(base, "No recognised model-listing endpoint responded; not identified as an inference API")
            continue
        asset = ctx.asset(AssetSpec(type="llm_endpoint", identifier=base, name=f"Inference endpoint {base.split('//', 1)[-1]}",
                                    exposure=_exposure(first), attributes={"api_style": kind, "models": models[:50]},
                                    ai={"provider": "ollama" if kind == "ollama" else None}))
        ai = ctx.db.get(AIAsset, asset.id)
        common: dict[str, Any] = {"asset": asset, "source": ctx.source, "domain": "ai_infra"}
        if not base.startswith("https://"):
            ctx.finding(FindingInput(**common, rule_id="ai.endpoint.plaintext", severity="medium", confidence="confirmed", cwe="CWE-319",
                                     title="Inference endpoint is served over plaintext HTTP",
                                     description="Prompts, completions and API keys are exposed to network observers.",
                                     remediation="Terminate TLS in front of the inference server.",
                                     evidence=[EvidenceInput("http_exchange", f"GET {base}", {"url": base, "scheme": "http"})]))
        if kind is None:
            if ai:
                ai.auth_required = True
            ctx.mark_complete(asset)
            continue
        if ai:
            ai.auth_required = False
            headers = {k for r in observed.values() for k in r.headers}
            ai.rate_limited = any(h.startswith(("x-ratelimit", "ratelimit")) or h == "retry-after" for h in headers) or None
        r = observed[open_path]
        ctx.finding(FindingInput(
            **common, rule_id="ai.endpoint.unauthenticated", severity="critical" if asset.exposure == "internet" else "high",
            confidence="confirmed", cwe="CWE-306", owasp_llm="LLM10:2025", atlas_technique="AML.T0040",
            title=f"Inference API is accessible without authentication ({len(models)} model(s) listed)",
            description=f"GET {open_path} returned the model list without credentials ({kind} API). Endpoints that list models "
                        "unauthenticated normally accept unauthenticated generation requests as well; generation was not attempted.",
            technical_impact="Unmetered use of GPU capacity, model extraction, and access to any private or fine-tuned models served.",
            remediation="Place the server behind an authenticating gateway with per-client keys and rate limits; bind local runtimes to localhost.",
            reproduction=f"curl -s {base}{open_path}",
            evidence=[EvidenceInput("http_exchange", f"GET {base}{open_path} -> HTTP {r.status_code}", {
                "request": {"method": "GET", "url": base + open_path, "headers": {}},
                "response": {"status": r.status_code, "models": models[:25], "body_excerpt": r.text()[:300]}})]))
        if ai and ai.rate_limited is None:
            ctx.finding(FindingInput(**common, rule_id="ai.endpoint.no_rate_limit_signal", severity="low", confidence="tentative",
                                     owasp_llm="LLM10:2025", title="Inference API returns no rate-limit headers",
                                     description="No RateLimit or X-RateLimit headers were observed. This suggests, but does not prove, that requests are not throttled.",
                                     remediation="Enforce per-client request and token limits at a gateway.",
                                     evidence=[EvidenceInput("http_exchange", f"Response headers from {base}{open_path}", {"headers": sorted(r.headers)[:40]})]))
        for model in models[:50]:
            m = ctx.asset(AssetSpec(type="ai_model", identifier=f"{base}#{model}", name=f"Model {model}", exposure=asset.exposure,
                                    attributes={"served_by": base}))
            ctx.link(asset, m, "EXPOSES")
        ctx.mark_complete(asset)


register(EngineSpec(kind="mcp_probe", name="MCP server probe", module="ai_security", run=run_mcp_probe, config_model=McpProbeConfig,
                    description="Performs the MCP handshake and lists tools, resources and prompts to assess authentication, transport, "
                                "tool-description poisoning indicators and exposed capabilities. Never invokes a tool.",
                    target_kinds=("url",), active=True))
register(EngineSpec(kind="ai_endpoint_probe", name="Inference endpoint probe", module="ai_security", run=run_endpoint_probe,
                    config_model=EndpointProbeConfig, target_kinds=("url",), active=True,
                    description="Checks OpenAI-compatible (vLLM, NIM, LiteLLM) and Ollama endpoints for unauthenticated model listing, "
                                "plaintext transport and missing rate-limit signals. Does not generate text."))
