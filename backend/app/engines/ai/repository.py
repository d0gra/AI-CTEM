"""Repository analysis: AI asset discovery, AI credential exposure, MCP configuration review,
model artifact inspection and dependency vulnerability analysis.

Operates on a local checkout under CTEM_REPO_SCAN_ROOT. Files are read, never executed.
"""

import json
import os
import re
import tomllib
from pathlib import Path

from pydantic import BaseModel, Field

from app.db.base import utcnow
from app.domains.assessments.service import EngineContext, EngineSpec, register
from app.domains.assets.service import AssetSpec
from app.domains.findings.service import EvidenceInput, FindingInput
from app.domains.risk.policy import load_policy
from app.engines.ai import mcp_analysis, model_scan
from app.engines.ai.signatures import (
    BY_KEY, CODE_EXECUTION_FORMATS, ENV_INDEX, MCP_CONFIG_NAMES, MCP_CONFIG_PARENTS, MODEL_EXTENSIONS, NPM_INDEX,
    PYPI_INDEX, SECRET_PATTERNS, SIGNATURES, AISignature,
)
from app.engines.scanners import analyse_components
from app.integrations.scanners.parsers import SbomComponent
from app.models import AIAsset, AIIntegration, AIModel, Asset, MCPServer

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build", ".next", "target", ".tox",
             ".mypy_cache", ".pytest_cache", "vendor", ".terraform", "site-packages"}
TEXT_EXTENSIONS = {".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".go", ".java", ".rb", ".cs", ".php", ".rs", ".kt",
                   ".yaml", ".yml", ".json", ".toml", ".env", ".cfg", ".ini", ".tf", ".sh", ".ipynb", ".md", ".txt", ""}
MAX_TEXT_BYTES = 1024 * 1024
PLACEHOLDER = re.compile(r"(x{6,}|your[_-]?(api[_-]?)?key|example|placeholder|changeme|<[^>]+>|\.\.\.|0{12,}|1234567890)", re.I)
PY_IMPORT = re.compile(r"^\s*(?:from|import)\s+([A-Za-z_][\w.]*)", re.M)
JS_IMPORT = re.compile(r"""(?:from\s+|require\(\s*|import\(\s*)['"]([^'"]+)['"]""")
URL_HOST = re.compile(r"https?://([A-Za-z0-9.\-]+(?::\d+)?)")


class RepositoryConfig(BaseModel):
    ai_discovery: bool = True
    secret_detection: bool = True
    mcp_configuration: bool = True
    model_artifacts: bool = True
    dependency_vulnerabilities: bool = Field(default=True, description="Query OSV for pinned dependencies (outbound request to api.osv.dev)")
    max_files: int = Field(default=20000, ge=100, le=200000)


def _walk(root: Path, max_files: int):
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            if path.is_symlink():
                continue
            count += 1
            if count > max_files:
                return
            yield path


def _read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_TEXT_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def parse_dependencies(path: Path, text: str) -> list[SbomComponent]:
    """Extract (name, exact version) pairs from a manifest or lockfile. Unpinned entries have version ''."""
    name = path.name
    out: list[SbomComponent] = []
    try:
        if name.startswith("requirements") and name.endswith(".txt"):
            for line in text.splitlines():
                m = re.match(r"^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(?:==\s*([A-Za-z0-9_.\-+!]+))?", line.split("#")[0])
                if m and m.group(1) and not line.strip().startswith(("-", "#")):
                    out.append(SbomComponent(m.group(1).lower(), m.group(2) or "", None, "PyPI"))
        elif name in ("uv.lock", "poetry.lock"):
            for pkg in tomllib.loads(text).get("package", []):
                out.append(SbomComponent(str(pkg.get("name", "")).lower(), str(pkg.get("version", "")), None, "PyPI"))
        elif name == "pyproject.toml":
            doc = tomllib.loads(text)
            deps = list((doc.get("project") or {}).get("dependencies") or [])
            deps += list(((doc.get("tool") or {}).get("poetry") or {}).get("dependencies") or {})
            for dep in deps:
                m = re.match(r"^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(?:==\s*([A-Za-z0-9_.\-+!]+))?", str(dep))
                if m and m.group(1).lower() != "python":
                    out.append(SbomComponent(m.group(1).lower(), m.group(2) or "", None, "PyPI"))
        elif name == "package-lock.json":
            for key, pkg in (json.loads(text).get("packages") or {}).items():
                if key.startswith("node_modules/") and pkg.get("version"):
                    out.append(SbomComponent(key.split("node_modules/")[-1], str(pkg["version"]), None, "npm"))
        elif name == "package.json":
            doc = json.loads(text)
            for section in ("dependencies", "devDependencies"):
                for dep, spec in (doc.get(section) or {}).items():
                    exact = spec if re.fullmatch(r"\d+\.\d+\.\d+[\w.\-+]*", str(spec)) else ""
                    out.append(SbomComponent(dep, exact, None, "npm"))
    except (ValueError, tomllib.TOMLDecodeError, AttributeError):
        return []
    return [c for c in out if c.name]


class _Scan:
    def __init__(self, ctx: EngineContext, root: Path, repo: Asset, config: RepositoryConfig):
        self.ctx, self.root, self.repo, self.config = ctx, root, repo, config
        self.detections: dict[tuple[str, str, str], dict] = {}  # (provider, method, location) -> detail
        self.components: dict[tuple[str, str, str], SbomComponent] = {}
        self.approved = {p.lower() for p in load_policy(ctx.db, ctx.assessment.organization_id).approved_ai_providers}
        self.counts = {"files": 0, "mcp_servers": 0, "model_artifacts": 0, "secrets": 0}

    def rel(self, path: Path) -> str:
        return str(path.relative_to(self.root))

    def detect(self, sig: AISignature, method: str, location: str, **detail) -> None:
        self.detections.setdefault((sig.key, method, location[:700]), {"sig": sig, **detail})

    # --- per-file analysis ---
    def manifest(self, path: Path, text: str) -> None:
        lock = path.name in ("uv.lock", "poetry.lock", "package-lock.json")
        for comp in parse_dependencies(path, text):
            index = PYPI_INDEX if comp.ecosystem == "PyPI" else NPM_INDEX
            sig = index.get(comp.name.lower())
            if sig and (not lock or comp.name.lower() in index):
                self.detect(sig, "dependency", f"{self.rel(path)}#{comp.name}", package=comp.name, version=comp.version or None)
            if comp.version:
                self.components[(comp.ecosystem or "", comp.name, comp.version)] = comp

    def source(self, path: Path, text: str) -> None:
        rel = self.rel(path)
        roots: set[str] = set()
        if path.suffix == ".py":
            roots = {m.split(".")[0] if not m.startswith(("google.", "azure.")) else ".".join(m.split(".")[:3]) for m in PY_IMPORT.findall(text)}
            roots |= set(PY_IMPORT.findall(text))
        elif path.suffix in (".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs"):
            roots = set(JS_IMPORT.findall(text))
        for sig in SIGNATURES:
            if roots & set(sig.imports):
                self.detect(sig, "import", rel)
        for host in set(URL_HOST.findall(text)):
            for sig in SIGNATURES:
                if any(h in host for h in sig.hosts if not h.startswith(":")) or any(host.endswith(h) for h in sig.hosts if h.startswith(":")):
                    self.detect(sig, "endpoint", f"{rel}#{host}", host=host)
        for env, sig in ENV_INDEX.items():
            if env in text:
                self.detect(sig, "config", f"{rel}#{env}", env_var=env)

    def secrets(self, path: Path, text: str) -> None:
        rel = self.rel(path)
        for rule, provider, label, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(text):
                value = match.group(0)
                if PLACEHOLDER.search(value) or len(set(value)) < 12:
                    continue  # documentation placeholder, not a credential
                line = text.count("\n", 0, match.start()) + 1
                self.counts["secrets"] += 1
                if provider in BY_KEY:
                    self.detect(BY_KEY[provider], "secret", f"{rel}:{line}")
                self.ctx.finding(FindingInput(
                    asset=self.repo, source=self.ctx.source, rule_id=f"ai.secret.{rule}", domain="secrets", severity="critical",
                    confidence="firm", cwe="CWE-798", discriminator=f"{rel}:{line}", owasp_llm="LLM02:2025",
                    title=f"{label} committed to source: {rel}:{line}",
                    description=f"A string matching the {label} format is present in the repository. The value is not stored by this platform; "
                                "only its public prefix is recorded. Whether the key is still active has not been tested.",
                    technical_impact="Anyone with repository access can use the provider account: incurring cost, reading stored data, "
                                     "and accessing fine-tuned models or files.",
                    remediation="Revoke the key at the provider, issue a new one from a secret manager, and purge the value from version history.",
                    evidence=[EvidenceInput("file", f"Credential pattern in {rel}", {"file": rel, "line": line, "prefix": match.group(1),
                                                                                     "length": len(value), "rule": rule})]))

    def mcp_config(self, path: Path, text: str) -> None:
        try:
            doc = json.loads(text)
        except ValueError:
            return
        servers = doc.get("mcpServers") or doc.get("servers") or (doc.get("mcp") or {}).get("servers") if isinstance(doc, dict) else None
        if not isinstance(servers, dict):
            return
        rel = self.rel(path)
        for name, definition in servers.items():
            if not isinstance(definition, dict):
                continue
            self.counts["mcp_servers"] += 1
            facts, issues = mcp_analysis.analyse_server_definition(str(name), definition)
            identifier = facts["endpoint"] or f"stdio:{self.repo.identifier}:{name}"
            asset = self.ctx.asset(AssetSpec(type="mcp_server", identifier=identifier, name=f"MCP server {name}",
                                             attributes={"declared_in": rel, "transport": facts["transport"]},
                                             ai={"provider": "mcp", "managed": False}))
            row = self.ctx.db.get(MCPServer, asset.id)
            if row is None:
                row = MCPServer(organization_id=asset.organization_id, asset_id=asset.id, transport=facts["transport"])
                self.ctx.db.add(row)
            row.transport, row.endpoint, row.command = facts["transport"], facts["endpoint"], facts["command"]
            row.auth_type, row.uses_tls, row.config_source = facts["auth_type"], facts["uses_tls"], rel
            self.ctx.link(self.repo, asset, "INVOKES_TOOL", evidence={"config": rel}, confidence=0.9)
            for i in issues:
                self.ctx.finding(FindingInput(
                    asset=asset, source=self.ctx.source, rule_id=i["rule"], domain="ai_mcp", title=i["title"], severity=i["severity"],
                    confidence=i["confidence"], description=i["description"], remediation=i["remediation"], discriminator=rel,
                    owasp_llm="LLM03:2025" if "unpinned" in i["rule"] else "LLM06:2025", atlas_technique="AML.T0053",
                    evidence=[EvidenceInput("config", f"MCP server definition '{name}' in {rel}", {"file": rel, "server": name, **i["evidence"]})]))
            self.ctx.mark_complete(asset)

    def model_artifact(self, path: Path, fmt: str) -> None:
        rel = self.rel(path)
        size = path.stat().st_size
        if fmt == "binary" and size < 1024 * 1024:
            return  # small .bin files are rarely model weights
        self.counts["model_artifacts"] += 1
        digest = model_scan.sha256_file(path) if size <= model_scan.MAX_SCAN_BYTES else None
        asset = self.ctx.asset(AssetSpec(type="ai_model", identifier=f"{self.repo.identifier}/{rel}", name=f"Model artifact {path.name}",
                                         attributes={"format": fmt, "path": rel, "size_bytes": size}, ai={"managed": False}))
        row = self.ctx.db.get(AIModel, asset.id)
        if row is None:
            row = AIModel(organization_id=asset.organization_id, asset_id=asset.id, model_name=path.name)
            self.ctx.db.add(row)
        row.artifact_format, row.sha256, row.size_bytes, row.source_uri = fmt, digest, min(size, 2**31 - 1), rel
        row.last_scanned_at = utcnow()
        self.ctx.link(self.repo, asset, "CONTAINS")
        common = {"asset": asset, "source": self.ctx.source, "domain": "ai_model", "owasp_llm": "LLM03:2025", "discriminator": rel}
        inspection = model_scan.inspect(path, fmt)
        if inspection["dangerous"]:
            refs = ", ".join(d["import"] for d in inspection["dangerous"][:6])
            self.ctx.finding(FindingInput(
                **common, rule_id="ai.model.pickle_code_execution", severity="high", confidence="firm", cwe="CWE-502",
                atlas_technique="AML.T0010", title=f"Model artifact imports code-execution callables when loaded: {path.name}",
                description=f"Disassembling the pickle stream (without executing it) shows that loading this file imports: {refs}. "
                            "Legitimate model checkpoints do not need these callables. This is evidence that loading the file executes code; "
                            "it does not by itself establish intent, so the artifact should be reviewed before any use.",
                technical_impact="Arbitrary code runs with the privileges of any process that loads the model.",
                remediation="Do not load the file. Obtain the model from a verified source in safetensors format, or review the pickle with a "
                            "dedicated scanner in an isolated environment.",
                evidence=[EvidenceInput("file", f"Pickle opcode analysis of {rel}", {"file": rel, "sha256": digest, "format": fmt,
                                                                                     "dangerous_imports": inspection["dangerous"][:25],
                                                                                     "all_imports": inspection["imports"][:60]})]))
        elif fmt in CODE_EXECUTION_FORMATS:
            self.ctx.finding(FindingInput(
                **common, rule_id="ai.model.unsafe_serialization", severity="medium", confidence="confirmed", cwe="CWE-502",
                title=f"Model artifact uses a serialization format that can execute code: {path.name}",
                description=f"{fmt} files are deserialized with pickle, which runs callables named in the file. "
                            + ("Opcode analysis found no code-execution imports in this file, which lowers but does not eliminate the risk."
                               if inspection["scanned"] else "The file was not analysed (too large or unreadable)."),
                remediation="Convert to safetensors, or load only with weights_only=True from a source whose integrity is verified.",
                evidence=[EvidenceInput("file", f"Model artifact {rel}", {"file": rel, "sha256": digest, "format": fmt, "size_bytes": size,
                                                                          "pickle_streams": inspection["streams"],
                                                                          "imports_sample": inspection["imports"][:30]})]))
        if row.provenance_verified is not True:
            self.ctx.finding(FindingInput(
                **common, rule_id="ai.model.provenance_unverified", severity="low", confidence="confirmed", nist_ai_rmf="MAP 4.1",
                title=f"Model artifact has no verified provenance: {path.name}",
                description="No source, signature or attestation is recorded for this artifact in the inventory.",
                remediation="Record the origin and expected digest of the model (or a Sigstore/model-signing attestation) and mark provenance verified.",
                evidence=[EvidenceInput("file", f"Model artifact {rel}", {"file": rel, "sha256": digest})]))
        self.ctx.mark_complete(asset)

    # --- aggregation ---
    def record_integrations(self) -> None:
        now = utcnow()
        by_provider: dict[str, list[tuple[str, str, dict]]] = {}
        for (provider, method, location), detail in self.detections.items():
            by_provider.setdefault(provider, []).append((method, location, detail))
        for provider, items in by_provider.items():
            sig: AISignature = items[0][2]["sig"]
            asset_type = {"provider": "ai_provider", "framework": "ai_framework", "vector_db": "vector_database", "serving": "ai_provider",
                          "mcp": "ai_framework", "registry": "model_registry"}[sig.category]
            approval = "unknown"
            if sig.category in ("provider", "serving") and self.approved:
                approval = "approved" if provider in self.approved else "unapproved"
            ai_asset = self.ctx.asset(AssetSpec(
                type=asset_type, identifier=f"{sig.key}@{self.repo.identifier}", name=f"{sig.name} in {self.repo.name}",
                attributes={"category": sig.category, "detections": len(items), "agentic_framework": bool(sig.extra.get("agentic")),
                            "methods": sorted({m for m, _, _ in items})},
                ai={"provider": sig.key, "framework": sig.key if sig.category == "framework" else None, "managed": False}))
            row = self.ctx.db.get(AIAsset, ai_asset.id)
            if row is not None and row.approval_status in ("unknown", "unapproved", "approved") and approval != "unknown":
                row.approval_status = approval
            self.ctx.link(self.repo, ai_asset, "DEPENDS_ON", evidence={"methods": sorted({m for m, _, _ in items})})
            for method, location, detail in items[:200]:
                existing = self.ctx.db.query(AIIntegration).filter_by(source_asset_id=self.repo.id, provider=provider,
                                                                      detection_method=method, location=location).one_or_none()
                if existing is None:
                    self.ctx.db.add(AIIntegration(
                        organization_id=self.repo.organization_id, source_asset_id=self.repo.id, ai_asset_id=ai_asset.id,
                        provider=provider, category=sig.category, package=detail.get("package"), version=detail.get("version"),
                        detection_method=method, location=location, first_seen_at=now, last_seen_at=now))
                else:
                    existing.last_seen_at = now
            if approval == "unapproved":
                sample = [loc for _m, loc, _d in items[:8]]
                self.ctx.finding(FindingInput(
                    asset=ai_asset, source=self.ctx.source, rule_id="ai.shadow.unapproved_provider", domain="shadow_ai", severity="medium",
                    confidence="confirmed", nist_ai_rmf="GOVERN 6.1", title=f"Unapproved AI provider in use: {sig.name} ({self.repo.name})",
                    description=f"{sig.name} is used by this repository but is not on the organization's approved AI provider list "
                                f"({', '.join(sorted(self.approved))}).",
                    business_impact="Data may be sent to a provider without a reviewed contract, data-processing terms or retention controls.",
                    remediation="Review the integration with the AI governance owner: approve the provider, or migrate to an approved one.",
                    evidence=[EvidenceInput("file", f"{sig.name} detections", {"locations": sample, "methods": sorted({m for m, _, _ in items})})]))
            self.ctx.mark_complete(ai_asset)
        self.ctx.db.flush()


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
        repo = ctx.asset(AssetSpec(type="repository", identifier=str(root), name=root.name))
        scan = _Scan(ctx, root, repo, config)
        ctx.job.progress(5, f"Reading {root.name}")
        for path in _walk(root, config.max_files):
            ctx.checkpoint()
            scan.counts["files"] += 1
            suffix, name = path.suffix.lower(), path.name
            fmt = MODEL_EXTENSIONS.get(suffix)
            if fmt and config.model_artifacts:
                scan.model_artifact(path, fmt)
                continue
            if suffix not in TEXT_EXTENSIONS and not name.startswith(".env"):
                continue
            text = _read_text(path)
            if text is None:
                continue
            is_manifest = name in ("pyproject.toml", "package.json", "package-lock.json", "uv.lock", "poetry.lock") or (
                name.startswith("requirements") and name.endswith(".txt"))
            if is_manifest:
                scan.manifest(path, text)
            if config.mcp_configuration and suffix == ".json" and (name in MCP_CONFIG_NAMES or (name == "mcp.json" or path.parent.name in MCP_CONFIG_PARENTS and "mcp" in name)):
                scan.mcp_config(path, text)
            if config.ai_discovery and not is_manifest and name not in ("package-lock.json",):
                scan.source(path, text)
            if config.secret_detection and name not in ("package-lock.json", "uv.lock", "poetry.lock"):
                scan.secrets(path, text)
        if config.ai_discovery:
            scan.record_integrations()
        ctx.stats.update(scan.counts)
        ctx.stats["ai_technologies"] = sorted({k[0] for k in scan.detections})
        if config.dependency_vulnerabilities and scan.components:
            ctx.job.progress(70, "Checking dependencies against OSV")
            ctx.stats.update(analyse_components(ctx, repo, list(scan.components.values()), ctx.source))
        ctx.mark_complete(repo)


register(EngineSpec(
    kind="repository_analysis", name="Repository AI and supply-chain analysis", module="ai_security", run=run,
    description="Discovers AI providers, frameworks, vector databases and MCP servers used by a codebase; detects committed AI "
                "credentials; reviews MCP client configuration; inspects model artifacts; checks pinned dependencies against OSV.",
    config_model=RepositoryConfig, target_kinds=("path",),
))
