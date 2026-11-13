"""Turn the signals collected while reading files into the AI inventory and its relationships."""

from __future__ import annotations

import re

from aictem.catalog import ASSET_TYPE, BY_KEY, HIGH_IMPACT
from aictem.detectors import Context
from aictem.model import Finding, Location

TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|spec|fixtures?|testdata|e2e)/|(^|/)test_[^/]*$|_test\.\w+$|\.(test|spec)\.\w+$|(^|/)conftest\.py$")

METHOD_WEIGHT = {"lockfile": 1, "dependency": 3, "import": 3, "iac": 3, "code": 2, "container": 2, "endpoint": 2, "secret": 2, "config": 1}


def build(ctx: Context, approved: set[str] | None) -> None:
    inv, repo = ctx.inventory, ctx.repo
    by_tech: dict[str, list] = {}
    for s in ctx.signals:
        by_tech.setdefault(s.tech.key, []).append(s)

    tech_assets = {}
    for key, signals in sorted(by_tech.items()):
        tech = BY_KEY[key]
        methods = sorted({s.method for s in signals})
        # An environment variable alone (for example GOOGLE_API_KEY) is weak evidence; keep it, but say so.
        evidence = "strong" if max(METHOD_WEIGHT.get(m, 1) for m in methods) >= 2 else "weak"
        if all(TEST_PATH.search(s.location.file) for s in signals):
            evidence = "tests_only"  # referenced only by tests or fixtures
        elif methods == ["lockfile"]:
            evidence = "transitive"  # only in a lockfile: pulled in by another dependency
        approval = "unknown"
        if approved and tech.category in ("provider", "serving"):
            approval = "approved" if key in approved else "unapproved"
        asset = inv.add(ASSET_TYPE[tech.category], f"{key}@{repo.identifier}", f"{tech.name} in {repo.name}",
                        attributes={"technology": tech.name, "category": tech.category, "detections": len(signals), "methods": methods,
                                    "evidence": evidence, "agentic_framework": tech.agentic or None,
                                    "packages": sorted({f"{s.package}@{s.version}" if s.version else s.package for s in signals if s.package}),
                                    "models": sorted(ctx.models_referenced.get(key, set()))[:50] or None,
                                    "usage": [{"method": s.method, "location": s.location.text(), "package": s.package, "version": s.version}
                                              for s in signals[:200]],
                                    "approval": approval if approval != "unknown" else None},
                        ai={"provider": key, "framework": key if tech.category in ("framework", "mcp") else None, "managed": False})
        asset.locations = [loc for loc in asset.locations if loc.method not in METHOD_WEIGHT]  # keep non-signal locations
        for s in sorted(signals, key=lambda s: -METHOD_WEIGHT.get(s.method, 1)):  # strongest evidence first
            if len(asset.locations) < 25 and s.location not in asset.locations:
                asset.locations.append(s.location)
        inv.link(repo, asset, "DEPENDS_ON", methods=methods)
        tech_assets[key] = asset
        if approval == "unapproved":
            inv.finding(Finding(
                rule_id="ai.shadow.unapproved_provider", title=f"Unapproved AI provider in use: {tech.name} ({repo.name})", severity="medium",
                domain="shadow_ai", asset=asset.ref, confidence="confirmed", nist_ai_rmf="GOVERN 6.1",
                description=f"{tech.name} is used by this repository but is not on the approved provider list ({', '.join(sorted(approved or []))}).",
                remediation="Review the integration with the AI governance owner: approve the provider, or migrate to an approved one.",
                evidence={"locations": [s.location.text() for s in signals[:8]], "methods": methods}))

    real = {k: a for k, a in tech_assets.items() if a.attributes.get("evidence") not in ("tests_only", "transitive")}
    uses_models = any(BY_KEY[k].category in ("provider", "serving") for k in real) or bool(ctx.endpoints)
    vector_stores = [a for k, a in real.items() if BY_KEY[k].category == "vector_db"]
    rag_framework = any(BY_KEY[k].rag for k in real)
    is_rag = bool(ctx.rag_markers) and (bool(vector_stores) or rag_framework)
    app = None
    if uses_models or is_rag or ctx.agent_files:
        app = inv.add("rag_application" if is_rag else "ai_application", f"app@{repo.identifier}",
                      f"{repo.name} ({'RAG application' if is_rag else 'AI application'})",
                      attributes={"providers": sorted(k for k in real if BY_KEY[k].category in ("provider", "serving")),
                                  "frameworks": sorted(k for k in real if BY_KEY[k].category in ("framework", "mcp")),
                                  "vector_stores": sorted(k for k in real if BY_KEY[k].category == "vector_db"),
                                  "retrieval_files": sorted(ctx.rag_markers)[:50] or None,
                                  "retrieval_markers": sorted({m for ms in ctx.rag_markers.values() for m in ms})[:30] or None,
                                  "agents": len(ctx.agent_files) or None},
                      ai={"provider": next((k for k in real if BY_KEY[k].category == "provider"), None), "managed": False})
        inv.link(repo, app, "CONTAINS")
        for key, asset in real.items():
            category = BY_KEY[key].category
            if category == "vector_db":
                inv.link(app, asset, "RETRIEVES_FROM")
            elif category in ("provider", "serving"):
                inv.link(app, asset, "CONNECTS_TO")
            else:
                inv.link(app, asset, "DEPENDS_ON")

    for origin, location in sorted(ctx.endpoints.items()):
        endpoint = inv.add("llm_endpoint", origin, f"Inference endpoint {origin}", attributes={"referenced_in": [location.file],
                                                                                              "self_hosted": True}, location=location)
        if app:
            inv.link(app, endpoint, "CONNECTS_TO", referenced_in=location.file)

    # MCP tool modules belong to the server implemented in the nearest enclosing directory.
    local_servers = [s for s in inv.of_type("mcp_server") if s.identifier.startswith("local:")]
    for tool_rel, defined in sorted(ctx.mcp_tool_files.items()):
        def depth(server, rel=tool_rel):
            base = server.attributes["implemented_in"].rsplit("/", 1)[0] if "/" in server.attributes["implemented_in"] else ""
            parts = [p for p in base.split("/") if p not in ("src", "server", "lib")]
            return len(parts) if rel.startswith(base.rsplit("/server", 1)[0]) else -1
        owner = max(local_servers, key=depth, default=None)
        if owner is None or depth(owner) < 0:
            from aictem.detectors.code import _mcp_server_impl

            _mcp_server_impl(ctx, tool_rel, "", defined)
            continue
        existing = owner.attributes.setdefault("tools", [])
        for tool in defined:
            if not any(t["name"] == tool["name"] for t in existing) and len(existing) < 200:
                existing.append({**{k: v for k, v in tool.items() if k != "poisoning"}, "defined_in": tool_rel})
        owner.attributes["high_impact_tools"] = sorted({t["name"] for t in existing if HIGH_IMPACT & set(t["capabilities"])})

    # Tools defined in other modules belong to the agents that reference them (usually by importing them).
    unattached: list[dict] = []
    for tool_rel, defined in sorted(ctx.tool_files.items()):
        for tool in defined:
            users = [info for info in ctx.agent_files.values() if tool["name"] in info["identifiers"]]
            if not users and len(ctx.agent_files) == 1:
                users = list(ctx.agent_files.values())
            for info in users:
                if not any(t["name"] == tool["name"] for t in info["tools"]):
                    info["tools"].append({**tool, "defined_in": tool_rel})
            if not users:
                unattached.append({**{k: v for k, v in tool.items() if k != "poisoning"}, "defined_in": tool_rel})
    if app and unattached:
        app.attributes["tools_without_agent"] = unattached[:100]

    for rel, info in sorted(ctx.agent_files.items()):
        tools = info["tools"]
        high = [t for t in tools if HIGH_IMPACT & set(t["capabilities"])]
        agent = inv.add("ai_agent", f"agent:{repo.identifier}:{rel}", f"Agent {info['name']} ({rel})" if info.get("name") else f"Agent in {rel}",
                        attributes={"frameworks": info["frameworks"], "defined_in": rel, "agent_name": info.get("name"), "roles": info.get("roles") or None,
                                    "tools": [{k: v for k, v in t.items() if k != "poisoning"} for t in tools][:100],
                                    "high_impact_tools": [t["name"] for t in high], "approval_step_detected": info["approval"],
                                    "uses_mcp": info["uses_mcp"]},
                        ai={"provider": next((f for f in info["frameworks"] if f in BY_KEY), None), "managed": False},
                        location=Location(rel, info.get("line"), "code"))
        if app:
            inv.link(app, agent, "CONTAINS")
        for fw in info["frameworks"]:
            if fw in tech_assets:
                inv.link(agent, tech_assets[fw], "DEPENDS_ON")
        if info["uses_mcp"]:
            for server in inv.of_type("mcp_server"):
                inv.link(agent, server, "INVOKES_TOOL")
        if high and not info["approval"]:
            inv.finding(Finding(
                rule_id="ai.agent.high_impact_tools_without_approval", title=f"Agent in {rel} has high-impact tools and no approval step",
                severity="high" if any({"shell", "code_execution", "payment", "iam_admin"} & set(t["capabilities"]) for t in high) else "medium",
                domain="ai_agent", asset=agent.ref, confidence="tentative", file=rel, owasp_llm="LLM06:2025", atlas_technique="AML.T0053",
                description="The agent can call tools that " + ", ".join(sorted({c for t in high for c in t["capabilities"] if c in HIGH_IMPACT}))
                            + " and no human-approval mechanism was found in the same file. A prompt injection could make it take these actions.",
                remediation="Require human confirmation for high-impact tools (for example interrupt_before in LangGraph or needsApproval in the AI SDK), "
                            "and give each tool the narrowest credentials possible.",
                evidence={"tools": [{"name": t["name"], "capabilities": t["capabilities"]} for t in high][:20]}))

    ctx.repo.attributes.update({k: v for k, v in {
        "languages": dict(sorted(ctx.languages.items(), key=lambda kv: -kv[1])) or None, "ci_systems": sorted(ctx.ci_systems) or None,
        "ai_technologies": sorted(BY_KEY[k].name for k in tech_assets) or None}.items() if v})
