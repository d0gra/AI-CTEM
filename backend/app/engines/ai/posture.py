"""AI posture review: evaluates the declared configuration of inventoried AI assets.

Findings from this engine are derived from inventory attributes (agent tools, autonomy,
retrieval authorization, approval status) that were discovered or recorded by the owning team.
Each finding states the attribute it is based on; confidence is "firm", not "confirmed",
because the engine does not observe runtime behaviour.
"""

from sqlalchemy import select

from app.domains.assessments.service import EngineContext, EngineSpec, register
from app.domains.findings.service import EvidenceInput, FindingInput
from app.domains.policy.views import agent_tool_stats, tool_is_high_impact
from app.models import AIAgent, AIAsset, AIModel, Asset, AssetRelationship, MCPServer
from app.models.asset import AI_ASSET_TYPES


def run(ctx: EngineContext) -> None:
    db = ctx.db
    assets = list(db.execute(select(Asset).where(Asset.type.in_(AI_ASSET_TYPES), Asset.status != "retired")).scalars())
    if ctx.dry_run:
        ctx.planned(f"Evaluate posture rules over {len(assets)} inventoried AI assets (no network activity)")
        return
    ai = {a.asset_id: a for a in db.execute(select(AIAsset)).scalars()}
    agents = {a.asset_id: a for a in db.execute(select(AIAgent)).scalars()}
    mcps = {m.asset_id: m for m in db.execute(select(MCPServer)).scalars()}
    models = {m.asset_id: m for m in db.execute(select(AIModel)).scalars()}
    retrieval_sources: dict = {}
    for rel in db.execute(select(AssetRelationship).where(AssetRelationship.type == "RETRIEVES_FROM")).scalars():
        retrieval_sources.setdefault(rel.source_asset_id, []).append(rel.target_asset_id)
    by_id = {a.id: a for a in db.execute(select(Asset)).scalars()}

    for asset in assets:
        ctx.checkpoint()
        x, attrs = ai.get(asset.id), asset.attributes or {}

        def emit(rule: str, domain: str, severity: str, title: str, description: str, remediation: str, basis: dict,
                 owasp: str | None = None, atlas: str | None = None, nist: str | None = None, impact: str = "", _asset=asset) -> None:
            ctx.finding(FindingInput(
                asset=_asset, source=ctx.source, rule_id=rule, domain=domain, severity=severity, confidence="firm", title=title,
                description=description + " Basis: declared inventory configuration, not observed runtime behaviour.",
                remediation=remediation, technical_impact=impact, owasp_llm=owasp, atlas_technique=atlas, nist_ai_rmf=nist,
                evidence=[EvidenceInput("config", f"Inventory attributes of {_asset.name}", basis)]))

        if not (asset.owner_user_id or asset.owner_team_id) and asset.type not in ("ai_framework", "ai_provider", "model_registry"):
            emit("ai.governance.no_owner", "shadow_ai", "low", f"AI asset has no assigned owner: {asset.name}",
                 "No user or team is accountable for this AI asset.", "Assign an owning team.", {"owner": None, "type": asset.type},
                 nist="GOVERN 2.1")
        if x is not None and x.approval_status == "unapproved" and asset.type not in ("ai_provider",):
            emit("ai.governance.unapproved", "shadow_ai", "medium", f"Unapproved AI asset in use: {asset.name}",
                 "The asset is marked as not approved for use.", "Complete the AI intake review or decommission the asset.",
                 {"approval_status": x.approval_status}, nist="GOVERN 1.2")
        if x is not None and x.processes_sensitive_data and x.approval_status != "approved":
            emit("ai.data.sensitive_unapproved", "ai_llm", "high", f"Sensitive data is processed by an AI asset that is not approved: {asset.name}",
                 "The asset is recorded as processing sensitive data but has not been approved.",
                 "Stop sending sensitive data until the asset and its provider are approved, or apply redaction at the boundary.",
                 {"processes_sensitive_data": True, "approval_status": x.approval_status, "provider": x.provider}, owasp="LLM02:2025", nist="MAP 4.1",
                 impact="Regulated or confidential data may leave approved processing boundaries.")
        if x is not None and x.tenant_isolation == "not_enforced":
            emit("ai.isolation.tenant_not_enforced", "ai_rag" if asset.type in ("rag_application", "vector_database") else "ai_llm", "high",
                 f"Tenant isolation is not enforced: {asset.name}", "The asset serves multiple tenants without enforced isolation of context or data.",
                 "Partition indexes, memory and caches per tenant and enforce the tenant filter server-side.", {"tenant_isolation": "not_enforced"},
                 owasp="LLM08:2025", impact="One tenant's prompts or documents can be returned to another.")

        agent = agents.get(asset.id)
        if agent is not None:
            tools = [t for t in agent.tools or [] if isinstance(t, dict)]
            high, unapproved = agent_tool_stats(tools)
            risky = [{"name": t.get("name"), "capabilities": t.get("capabilities")} for t in tools if tool_is_high_impact(t) and not t.get("requires_approval")]
            if unapproved:
                emit("ai.agent.excessive_agency", "ai_agent", "high", f"Agent can invoke {unapproved} high-impact tool(s) without approval: {asset.name}",
                     "The agent holds tools that execute code, modify data, move money or change access, and they do not require confirmation.",
                     "Remove tools the agent does not need; require human approval for the remainder; scope credentials per tool.",
                     {"tools_without_approval": risky[:20]}, owasp="LLM06:2025", atlas="AML.T0053", nist="MANAGE 2.2",
                     impact="A successful prompt injection is converted directly into the listed actions.")
            if agent.autonomy_level == "autonomous" and not agent.human_approval_required and high:
                emit("ai.agent.uncontrolled_autonomy", "ai_agent", "high", f"Autonomous agent performs high-impact actions without human oversight: {asset.name}",
                     "The agent runs without a human in the loop and holds high-impact tools.",
                     "Introduce approval gates for irreversible actions and bound the agent's task scope.",
                     {"autonomy_level": agent.autonomy_level, "human_approval_required": agent.human_approval_required, "high_impact_tools": high},
                     owasp="LLM06:2025", nist="GOVERN 3.2")
            if agent.processes_untrusted_input and unapproved:
                emit("ai.agent.injection_to_action", "ai_agent", "critical", f"Untrusted content can drive high-impact tools: {asset.name}",
                     "The agent reads content it does not control (web pages, email, documents, tool output) and can call high-impact tools without approval. "
                     "This is the precondition for indirect prompt injection leading to unauthorized actions.",
                     "Separate untrusted-content handling from privileged tool use; require approval for actions triggered while untrusted content is in context.",
                     {"processes_untrusted_input": True, "tools_without_approval": risky[:20]}, owasp="LLM01:2025", atlas="AML.T0051.001",
                     impact="An attacker who can place text in front of the agent can trigger the listed actions.")
            if agent.persistent_memory and agent.processes_untrusted_input:
                emit("ai.agent.memory_poisoning", "ai_agent", "medium", f"Agent persists memory derived from untrusted input: {asset.name}",
                     "Instructions injected once can be stored and replayed in later sessions (persistent prompt injection).",
                     "Validate and attribute what is written to memory; isolate memory per user; expire entries.",
                     {"persistent_memory": True, "processes_untrusted_input": True}, owasp="LLM04:2025", atlas="AML.T0080")
            if agent.identity_asset_id is None and tools:
                emit("ai.agent.no_dedicated_identity", "ai_agent", "medium", f"Agent has no dedicated identity recorded: {asset.name}",
                     "No service identity is linked to the agent, so its actions cannot be attributed or scoped independently of its users or host.",
                     "Give the agent its own least-privilege identity and link it in the inventory.", {"identity_asset_id": None}, nist="GOVERN 2.1")
            elif agent.identity_asset_id and (by_id.get(agent.identity_asset_id) is not None) and (by_id[agent.identity_asset_id].attributes or {}).get("privileged"):
                emit("ai.agent.privileged_identity", "ai_agent", "high", f"Agent runs with a privileged identity: {asset.name}",
                     f"The agent authenticates as {by_id[agent.identity_asset_id].name}, which holds administrative permissions.",
                     "Replace with a role scoped to the agent's tools.", {"identity": by_id[agent.identity_asset_id].identifier}, owasp="LLM06:2025")
            if agent.can_delegate and not agent.human_approval_required:
                emit("ai.agent.unrestricted_delegation", "ai_agent", "medium", f"Agent can delegate to other agents without approval: {asset.name}",
                     "Delegated agents inherit instructions that may originate from untrusted content, extending the trust boundary.",
                     "Restrict which agents can be invoked and with what authority; do not forward privileges implicitly.",
                     {"can_delegate": True}, owasp="LLM06:2025")

        if asset.type in ("rag_application", "vector_database"):
            if attrs.get("document_level_authorization") is False:
                emit("ai.rag.no_document_authorization", "ai_rag", "high", f"Retrieval does not enforce document-level authorization: {asset.name}",
                     "Any user of the application can retrieve any indexed document, regardless of the source system's permissions.",
                     "Propagate source ACLs into the index and filter retrieval by the caller's entitlements.", {"document_level_authorization": False},
                     owasp="LLM08:2025", impact="Documents are disclosed to users who cannot access them in the source system.")
            if attrs.get("ingests_untrusted_content") and not attrs.get("ingestion_provenance_tracked"):
                emit("ai.rag.untrusted_ingestion", "ai_rag", "medium", f"Untrusted content is indexed without provenance: {asset.name}",
                     "Content from sources outside the organization's control is ingested and its origin is not recorded, enabling retrieval poisoning.",
                     "Record source and trust level per chunk; exclude or down-rank untrusted sources; scan content before indexing.",
                     {"ingests_untrusted_content": True, "ingestion_provenance_tracked": bool(attrs.get("ingestion_provenance_tracked"))},
                     owasp="LLM08:2025", atlas="AML.T0070")
            if attrs.get("contains_sensitive_data") and asset.data_sensitivity in ("unknown", "public", "internal"):
                emit("ai.rag.sensitive_data_unclassified", "ai_rag", "medium", f"Sensitive data is indexed but the store is not classified: {asset.name}",
                     "The store is recorded as containing sensitive data while its classification does not reflect that.",
                     "Classify the store and apply the matching access and retention controls.",
                     {"contains_sensitive_data": True, "data_sensitivity": asset.data_sensitivity}, owasp="LLM02:2025")
            if asset.exposure == "internet" and x is not None and x.auth_required is False:
                emit("ai.rag.vector_db_exposed", "ai_rag", "critical", f"Vector database is internet-exposed without authentication: {asset.name}",
                     "Embeddings and the source text stored with them can be read or overwritten by anyone.",
                     "Remove public exposure and enable authentication.", {"exposure": "internet", "auth_required": False}, owasp="LLM08:2025")
        if asset.type in ("llm_endpoint", "ai_application") and x is not None:
            if x.auth_required is False:
                emit("ai.endpoint.no_auth_declared", "ai_infra", "critical" if asset.exposure == "internet" else "high",
                     f"AI endpoint does not require authentication: {asset.name}", "The endpoint is recorded as accepting unauthenticated requests.",
                     "Require authentication for every caller.", {"auth_required": False, "exposure": asset.exposure}, owasp="LLM10:2025")
            if x.rate_limited is False:
                emit("ai.endpoint.no_rate_limit", "ai_infra", "medium", f"AI endpoint has no rate or token limits: {asset.name}",
                     "Unbounded requests allow cost exhaustion and model extraction.", "Enforce per-client request and token budgets.",
                     {"rate_limited": False}, owasp="LLM10:2025", atlas="AML.T0034")
        mcp = mcps.get(asset.id)
        if mcp is not None and mcp.transport != "stdio" and mcp.auth_type in ("none",):
            high_tools = [t["name"] for t in mcp.tools or [] if isinstance(t, dict) and tool_is_high_impact(t)]
            if high_tools:
                emit("ai.mcp.high_impact_no_auth", "ai_mcp", "high", f"MCP server without authentication offers high-impact tools: {asset.name}",
                     "The inventory records no client authentication for a server exposing tools that execute or modify.",
                     "Require authentication and per-tool authorization.", {"auth_type": mcp.auth_type, "tools": high_tools[:20]}, owasp="LLM06:2025")
        model = models.get(asset.id)
        if model is not None and asset.environment == "production" and model.provenance_verified is not True:
            emit("ai.model.production_unverified", "ai_model", "medium", f"Production model has no verified provenance: {asset.name}",
                 "A model used in production has no recorded, verified origin or integrity check.",
                 "Verify the artifact digest against the publisher's and record the attestation.",
                 {"provenance_verified": model.provenance_verified, "artifact_format": model.artifact_format}, owasp="LLM03:2025", nist="MAP 4.1")
        ctx.mark_complete(asset)
    ctx.stats["ai_assets_reviewed"] = len(assets)


register(EngineSpec(
    kind="ai_posture_review", name="AI posture review", module="ai_security", run=run,
    description="Evaluates inventoried AI agents, RAG systems, endpoints, MCP servers and models against least-privilege, "
                "oversight, isolation and provenance rules mapped to OWASP LLM Top 10, MITRE ATLAS and NIST AI RMF.",
))
