"""Import of `aictem discover` inventories (report format "aictem", schema aictem-inventory/1).

The CLI runs where the code is (a developer machine or a CI job) and reports assets, relationships and
findings. Everything is validated against the platform's own types before use; package versions are
checked against OSV here, so vulnerability data never depends on the client.
"""

from __future__ import annotations

import json

from app.domains.assessments.service import EngineContext
from app.domains.assets.service import AssetSpec
from app.domains.findings.service import EvidenceInput, FindingInput
from app.integrations.scanners.parsers import ReportFormatError, SbomComponent, _ecosystem
from app.models import AIAgent, AIIntegration, MCPServer
from app.models.asset import ASSET_TYPES, RELATIONSHIP_TYPES
from app.models.finding import CONFIDENCES, FINDING_DOMAINS

SCHEMA = "aictem-inventory/1"
MAX_ASSETS, MAX_FINDINGS, MAX_RELATIONSHIPS = 25_000, 20_000, 50_000
SEVERITIES = {"critical", "high", "medium", "low", "info"}
AI_KEYS = {"provider", "framework", "managed"}


def _clip(value, depth: int = 0):
    """Bound attribute payloads: strings, list lengths and nesting."""
    if isinstance(value, str):
        return value[:2000]
    if isinstance(value, list):
        return [_clip(v, depth + 1) for v in value[:200]] if depth < 4 else []
    if isinstance(value, dict):
        return {str(k)[:100]: _clip(v, depth + 1) for k, v in list(value.items())[:100]} if depth < 4 else {}
    return value if isinstance(value, (int, float, bool)) or value is None else str(value)[:500]


def parse(data: bytes) -> dict:
    try:
        doc = json.loads(data)
    except ValueError as exc:
        raise ReportFormatError("Not an aictem inventory: the file is not JSON") from exc
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        raise ReportFormatError(f"Not an aictem inventory (expected schema {SCHEMA!r}; produce it with `aictem discover --format json`)")
    for key, limit in (("assets", MAX_ASSETS), ("findings", MAX_FINDINGS), ("relationships", MAX_RELATIONSHIPS)):
        if not isinstance(doc.get(key, []), list) or len(doc.get(key, [])) > limit:
            raise ReportFormatError(f"Inventory '{key}' must be a list of at most {limit} entries")
    return doc


def ingest(ctx: EngineContext, data: bytes, target: str | None, source: str) -> None:
    doc = parse(data)
    refs = {}
    components: list[SbomComponent] = []
    skipped = 0
    items = [i for i in doc.get("assets") or [] if isinstance(i, dict)]
    items.sort(key=lambda i: i.get("type") != "repository")  # the repository first: other assets link to it
    repo = None
    for item in items:
        if not isinstance(item, dict) or item.get("type") not in ASSET_TYPES or not isinstance(item.get("identifier"), str) or not item["identifier"]:
            skipped += 1
            continue
        attributes = _clip(item.get("attributes") or {})
        if not isinstance(attributes, dict):
            attributes = {}
        locations = [loc for loc in item.get("locations") or [] if isinstance(loc, dict)][:25]
        if locations:
            attributes["locations"] = _clip(locations)
        if item["type"] == "package":
            purl = attributes.get("purl") or item["identifier"]
            if attributes.get("version") and attributes.get("package"):
                components.append(SbomComponent(name=str(attributes["package"]), version=str(attributes["version"]), purl=purl,
                                                ecosystem=attributes.get("ecosystem") or _ecosystem(purl)))
        ai = {k: v for k, v in (item.get("ai") or {}).items() if k in AI_KEYS} if isinstance(item.get("ai"), dict) else None
        if ai is not None and "managed" in ai:
            ai["managed"] = bool(ai["managed"])
        identifier = target if item["type"] == "repository" and target and repo is None else item["identifier"]
        asset = ctx.asset(AssetSpec(type=item["type"], identifier=identifier[:1000], name=str(item.get("name") or identifier)[:512],
                                    attributes=attributes, ai=ai or None))
        refs[item.get("ref") or f"{item['type']}:{item['identifier']}"] = asset
        if item["type"] == "repository" and repo is None:
            repo = asset
        if repo is None:
            raise ReportFormatError("The inventory has no repository asset")
        _extensions(ctx, asset, item["type"], attributes, repo)

    if components:  # versions checked against OSV by the platform
        from app.engines.scanners import analyse_components

        ctx.stats.update({f"packages_{k}": v for k, v in analyse_components(ctx, repo, components, source).items()})

    for rel in doc.get("relationships") or []:
        if not isinstance(rel, dict) or rel.get("type") not in RELATIONSHIP_TYPES:
            continue
        src, dst = refs.get(rel.get("source")), refs.get(rel.get("target"))
        if src is not None and dst is not None:
            ctx.link(src, dst, rel["type"], evidence=_clip(rel.get("evidence") or {}) or None, confidence=0.9)

    for f in doc.get("findings") or []:
        if not isinstance(f, dict) or f.get("severity") not in SEVERITIES or f.get("domain") not in FINDING_DOMAINS:
            skipped += 1
            continue
        if str(f.get("rule_id", "")).startswith("osv."):
            continue  # vulnerabilities come from the platform's own OSV lookup above
        asset = refs.get(f.get("asset")) or repo
        evidence = _clip(f.get("evidence") or {})
        where = {k: f[k] for k in ("file", "line") if f.get(k)}
        ctx.finding(FindingInput(
            asset=asset, source=source, rule_id=str(f.get("rule_id") or "aictem.unknown")[:200], domain=f["domain"],
            title=str(f.get("title") or f.get("rule_id"))[:500], severity=f["severity"], description=str(f.get("description") or "")[:5000],
            remediation=str(f.get("remediation") or "")[:3000], confidence=f.get("confidence") if f.get("confidence") in CONFIDENCES else "firm",
            cwe=f.get("cwe"), owasp_llm=f.get("owasp_llm"), atlas_technique=f.get("atlas_technique"), nist_ai_rmf=f.get("nist_ai_rmf"),
            discriminator=str(f.get("discriminator") or "")[:300], attributes=where,
            evidence=[EvidenceInput("file" if where else "config", f"{where.get('file', 'inventory')}"
                                    + (f":{where['line']}" if where.get("line") else ""), {**where, **(evidence if isinstance(evidence, dict) else {})})]))
    for asset in refs.values():
        ctx.mark_complete(asset)
    ctx.stats.update({"inventory_assets": len(refs), "inventory_skipped": skipped,
                      "inventory_tool": _clip((doc.get("tool") or {}).get("version"))})


def _extensions(ctx: EngineContext, asset, asset_type: str, attributes: dict, repo) -> None:
    """Fill AI extension rows the posture review reads: agent tools, MCP server facts, detected usage."""
    db = ctx.db
    if asset_type == "ai_agent" and isinstance(attributes.get("tools"), list):
        row = db.get(AIAgent, asset.id)
        if row is not None:
            approval = bool(attributes.get("approval_step_detected"))
            row.tools = [{"name": str(t.get("name"))[:200], "description": str(t.get("description") or "")[:500],
                          "capabilities": [str(c) for c in t.get("capabilities") or []][:15], "requires_approval": approval}
                         for t in attributes["tools"][:200] if isinstance(t, dict) and t.get("name")]
            if attributes.get("approval_step_detected"):
                row.human_approval_required = row.human_approval_required if row.human_approval_required is not None else True
    if asset_type == "mcp_server":
        row = db.get(MCPServer, asset.id)
        if row is None:
            row = MCPServer(organization_id=asset.organization_id, asset_id=asset.id, transport=str(attributes.get("transport") or "unknown")[:24])
            db.add(row)
        if attributes.get("auth_type"):
            row.auth_type = str(attributes["auth_type"])[:24]
        if attributes.get("command"):
            row.command = str(attributes["command"])[:1024]
        if attributes.get("uses_tls") is not None:
            row.uses_tls = bool(attributes["uses_tls"])
        if not str(asset.identifier).startswith(("stdio:", "local:")):
            row.endpoint = str(asset.identifier)[:1024]
        declared = attributes.get("declared_in")
        origin = declared[0] if isinstance(declared, list) and declared else attributes.get("implemented_in")
        if origin:
            row.config_source = str(origin)[:1024]
        if isinstance(attributes.get("tools"), list):
            row.tools = [{"name": str(t.get("name"))[:200], "description": str(t.get("description") or "")[:500],
                          "capabilities": [str(c) for c in t.get("capabilities") or []][:15]} for t in attributes["tools"][:200] if isinstance(t, dict)]
    usage = attributes.get("usage")
    if asset_type in ("ai_provider", "ai_framework", "vector_database", "model_registry") and isinstance(usage, list):
        from app.db.base import utcnow

        now = utcnow()
        provider = str(asset.identifier).split("@", 1)[0][:48]
        for u in usage[:200]:
            if not isinstance(u, dict) or not u.get("location"):
                continue
            key = {"source_asset_id": repo.id, "provider": provider, "detection_method": str(u.get("method") or "dependency")[:24],
                   "location": str(u["location"])[:700]}
            existing = db.query(AIIntegration).filter_by(**key).one_or_none()
            if existing is None:
                db.add(AIIntegration(organization_id=repo.organization_id, ai_asset_id=asset.id, category=str(attributes.get("category") or "provider")[:24],
                                     package=(str(u["package"])[:200] if u.get("package") else None),
                                     version=(str(u["version"])[:64] if u.get("version") else None), first_seen_at=now, last_seen_at=now, **key))
            else:
                existing.last_seen_at = now
