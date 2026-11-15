"""Repository analysis: AI assets, agents and their tools, MCP configuration, model artifacts, committed
credentials, containers, IaC, CI pipelines and dependency vulnerabilities.

The analysis itself is the `aictem` library, the same code as the `aictem discover` CLI, so a repository
gives the same result whether a worker reads it here or a pipeline uploads an inventory. This module
only decides what is read (a path under CTEM_REPO_SCAN_ROOT, inside the authorized scope) and hands
the inventory to the shared ingestion. Files are read, never executed.
"""

from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as StillRunning
from pathlib import Path

from aictem import gitinfo as aictem_git
from aictem import scan as aictem_scan
from pydantic import BaseModel, Field

from app.domains.assessments.service import EngineContext, EngineSpec, register
from app.engines import inventory_import

# A checkout on a worker is untrusted input, and git runs programs named in a repository's own configuration.
# The library asks git only which files are tracked, to grade committed credentials; a worker does without that
# and never starts git at all.
aictem_git.tracked_files = lambda root: None


def scan(ctx: EngineContext, root: Path, config: "RepositoryConfig") -> dict:
    """Run the library in a thread, heartbeating the job meanwhile: a large repository takes longer than the
    interval after which a silent job is treated as abandoned and started again."""
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="aictem") as pool:
        future = pool.submit(aictem_scan.run, root, secrets_enabled=config.secret_detection, max_files=config.max_files)
        while True:
            try:
                return future.result(timeout=2)
            except StillRunning:
                ctx.checkpoint()  # raises if the run was cancelled; the read-only scan then finishes unobserved


AI_TYPES = {"ai_application", "rag_application", "ai_agent", "ai_provider", "ai_framework", "vector_database", "model_registry", "llm_endpoint"}
AI_DOMAINS = {"ai_llm", "ai_rag", "ai_agent", "ai_infra", "shadow_ai"}
MCP_TYPES = {"mcp_server", "mcp_client"}


class RepositoryConfig(BaseModel):
    ai_discovery: bool = True
    secret_detection: bool = True
    mcp_configuration: bool = True
    model_artifacts: bool = True
    dependency_vulnerabilities: bool = Field(default=True, description="Query OSV for pinned dependencies (outbound request to api.osv.dev)")
    max_files: int = Field(default=20000, ge=100, le=200000)


def select(doc: dict, config: RepositoryConfig) -> dict:
    """Drop the parts of an inventory that the assessment's options switch off."""
    types, domains = set(), set()
    if not config.ai_discovery:
        types |= AI_TYPES
        domains |= AI_DOMAINS
    if not config.mcp_configuration:
        types |= MCP_TYPES
        domains.add("ai_mcp")
    if not config.model_artifacts:
        types.add("ai_model")
        domains.add("ai_model")
    if not types:
        return doc
    dropped = {a.get("ref") or f"{a['type']}:{a['identifier']}" for a in doc["assets"] if a["type"] in types}
    return {**doc,
            "assets": [a for a in doc["assets"] if a["type"] not in types],
            "relationships": [r for r in doc["relationships"] if r["source"] not in dropped and r["target"] not in dropped],
            "findings": [f for f in doc["findings"] if f["asset"] not in dropped and f["domain"] not in domains]}


def run(ctx: EngineContext) -> None:
    config: RepositoryConfig = ctx.config  # type: ignore[assignment]
    for target in ctx.targets:
        ctx.scope(target.value, active=False)
        root = Path(target.value).resolve()
        if ctx.dry_run:
            ctx.planned(f"Read files under {root} (no execution)" + ("; query api.osv.dev for pinned dependencies" if config.dependency_vulnerabilities else ""))
            continue
        if not root.is_dir():
            raise ValueError(f"{root} is not a directory on this worker")
        ctx.job.progress(5, f"Reading {root.name}")
        doc = select(scan(ctx, root, config), config)
        ctx.checkpoint()
        ctx.job.progress(60, "Recording the inventory")
        inventory_import.ingest_document(ctx, doc, None, ctx.source, vulnerabilities=config.dependency_vulnerabilities)

        summary = doc["summary"]
        ctx.stats.update({
            "files": summary["files"], "truncated": summary["truncated"], "unreadable_files": summary["errors"],
            "mcp_servers": sum(a["type"] == "mcp_server" for a in doc["assets"]),
            "model_artifacts": sum(a["type"] == "ai_model" and bool(a["attributes"].get("path")) for a in doc["assets"]),
            "agents": sum(a["type"] == "ai_agent" for a in doc["assets"]),
            "secrets": sum(f["domain"] == "secrets" for f in doc["findings"]),
            "ai_technologies": sorted(a["identifier"].split("@", 1)[0] for a in doc["assets"]
                                      if a["type"] in ("ai_provider", "ai_framework", "vector_database", "model_registry")),
        })
        for key in [k for k in ctx.stats if k.startswith("packages_")]:  # the names this engine has always reported
            ctx.stats[key.removeprefix("packages_")] = ctx.stats[key]


register(EngineSpec(
    kind="repository_analysis", permission="discovery:run", name="Repository AI and supply-chain analysis", module="ai_security", run=run,
    description="Runs the aictem discovery library on a checkout: AI providers, frameworks, agents and their tools, RAG pipelines, "
                "vector stores, MCP clients and servers, model artifacts, committed credentials, containers, IaC and CI pipelines; "
                "pinned dependencies are checked against OSV.",
    config_model=RepositoryConfig, target_kinds=("path",),
))
