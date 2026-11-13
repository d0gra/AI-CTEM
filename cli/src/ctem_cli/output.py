"""Report renderers: a terminal summary, JSON (the `ctem` upload format) and SARIF for code-scanning dashboards."""

from __future__ import annotations

import json
import os
import shutil
import sys

from ctem_cli import __version__
from ctem_cli.model import AI_ASSET_TYPES, SEVERITY_RANK

COLORS = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[2m", "bold": "\033[1m",
          "dim": "\033[2m", "green": "\033[32m", "reset": "\033[0m"}
TYPE_LABEL = {
    "repository": "Repository", "package": "Packages", "container_image": "Container images", "k8s_resource": "Kubernetes resources",
    "cloud_resource": "Cloud resources", "storage": "Storage", "database": "Databases", "load_balancer": "Load balancers", "identity": "Identities",
    "host": "Hosts", "api": "APIs", "ai_application": "AI applications", "rag_application": "RAG applications", "ai_agent": "AI agents",
    "llm_endpoint": "LLM endpoints", "ai_provider": "AI providers", "ai_framework": "AI frameworks", "vector_database": "Vector databases",
    "mcp_server": "MCP servers", "mcp_client": "MCP clients", "ai_model": "AI models", "model_registry": "Model registries",
}


class Painter:
    def __init__(self, stream) -> None:
        self.on = stream.isatty() and not os.environ.get("NO_COLOR") and os.environ.get("TERM") != "dumb"

    def __call__(self, text: str, style: str) -> str:
        return f"{COLORS[style]}{text}{COLORS['reset']}" if self.on else text


def table(report: dict, stream=None, *, show_all: bool = False) -> None:
    stream = stream or sys.stdout
    c = Painter(stream)
    width = min(shutil.get_terminal_size((110, 20)).columns, 140)
    w = stream.write
    s = report["summary"]
    t = report["target"]
    w(c(f"ctem {__version__}", "bold") + c(f"  {t['repository']}" + (f" @ {t['branch']}" if t.get("branch") else "")
                                              + (f" ({t['commit'][:10]})" if t.get("commit") else ""), "dim") + "\n")
    w(c(f"{s['files']} files, {s['source_files']} source, {s['manifests']} manifests, {s['model_files']} model files "
        f"in {report['duration_seconds']}s", "dim") + ("  " + c("(file limit reached; results are partial)", "medium") if s["truncated"] else "") + "\n\n")

    assets = report["assets"]
    w(c("Assets", "bold") + "\n")
    for kind, count in sorted(s["assets_by_type"].items(), key=lambda kv: (kv[0] not in AI_ASSET_TYPES, kv[0])):
        marker = c("AI ", "green") if kind in AI_ASSET_TYPES else "   "
        w(f"  {marker}{TYPE_LABEL.get(kind, kind):<24} {count:>5}\n")

    ai = [a for a in assets if a["type"] in AI_ASSET_TYPES]
    if ai:
        w("\n" + c(f"AI inventory ({len(ai)})", "bold") + "\n")
        for a in sorted(ai, key=lambda a: (a["type"], a["name"]))[: None if show_all else 40]:
            attrs = a.get("attributes") or {}
            detail = []
            if attrs.get("evidence") == "weak":
                detail.append("weak evidence: environment variable only")
            elif attrs.get("evidence") == "tests_only":
                detail.append("referenced only in tests")
            elif attrs.get("evidence") == "transitive":
                detail.append("transitive dependency only (lockfile)")
            if attrs.get("models"):
                detail.append("models: " + ", ".join(attrs["models"][:4]))
            if attrs.get("roles") and len(attrs["roles"]) > 1:
                detail.append(f"{len(attrs['roles'])} agents: " + ", ".join(attrs["roles"][:3]))
            if attrs.get("tools"):
                detail.append(f"{len(attrs['tools'])} tools" + (f", high impact: {', '.join(attrs['high_impact_tools'][:4])}" if attrs.get("high_impact_tools") else ""))
            if attrs.get("transport"):
                detail.append(attrs["transport"])
            if attrs.get("format"):
                detail.append(attrs["format"])
            where = a["locations"][0]["file"] + (f":{a['locations'][0]['line']}" if a["locations"][0].get("line") else "") if a.get("locations") else ""
            w(f"  {TYPE_LABEL.get(a['type'], a['type']):<17} {a['name'][:54]:<54} {c(where[:38], 'dim')}\n")
            if detail:
                w(f"  {'':<17} {c('; '.join(detail)[:width - 22], 'dim')}\n")
        if len(ai) > 40 and not show_all:
            w(c(f"  ... {len(ai) - 40} more (use --all)\n", "dim"))

    findings = report["findings"]
    w("\n" + c(f"Findings ({len(findings)})", "bold"))
    sev = s["findings_by_severity"]
    w("  " + "  ".join(c(f"{sev[k]} {k}", k) for k in ("critical", "high", "medium", "low", "info") if sev.get(k)) + "\n")
    for f in findings[: None if show_all else 30]:
        where = (f.get("file") or "") + (f":{f['line']}" if f.get("line") else "")
        label = f"{f['severity'].upper():<8}"
        w(f"  {c(label, f['severity'])} {f['title'][:width - 14]}\n")
        w(f"  {'':<8} {c(f['rule_id'] + ('  ' + where if where else ''), 'dim')}\n")
    if len(findings) > 30 and not show_all:
        w(c(f"  ... {len(findings) - 30} more (use --all, or --format json)\n", "dim"))
    if not findings:
        w(c("  none\n", "dim"))


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2, sort_keys=False, default=str) + "\n"


SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def to_sarif(report: dict) -> str:
    rules: dict[str, dict] = {}
    results = []
    for f in report["findings"]:
        rules.setdefault(f["rule_id"], {
            "id": f["rule_id"], "name": f["rule_id"].replace(".", "_"), "shortDescription": {"text": f["title"][:200]},
            "fullDescription": {"text": f.get("description") or f["title"]}, "help": {"text": f.get("remediation") or ""},
            "properties": {"security-severity": {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}[f["severity"]],
                           "tags": [t for t in ("security", f["domain"], f.get("owasp_llm"), f.get("cwe")) if t]}})
        location = {"physicalLocation": {"artifactLocation": {"uri": f.get("file") or "."},
                                         **({"region": {"startLine": f["line"]}} if f.get("line") else {})}}
        results.append({"ruleId": f["rule_id"], "level": SARIF_LEVEL[f["severity"]], "message": {"text": f["title"]}, "locations": [location],
                        "partialFingerprints": {"ctem/v1": f"{f['rule_id']}:{f.get('discriminator') or f.get('file') or ''}"}})
    doc = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
           "runs": [{"tool": {"driver": {"name": "ctem", "version": __version__, "informationUri": "https://github.com/d0gra/AI-CTEM",
                                         "rules": list(rules.values())}}, "results": results}]}
    return json.dumps(doc, indent=2) + "\n"


def worst(report: dict) -> str | None:
    ranks = [SEVERITY_RANK[f["severity"]] for f in report["findings"]]
    if not ranks:
        return None
    return next(k for k, v in SEVERITY_RANK.items() if v == max(ranks))
