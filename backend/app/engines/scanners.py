"""Scanner engines: result import, tool execution (nmap, nuclei, path-based scanners) and
dependency analysis against OSV."""

import ipaddress
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from pydantic import BaseModel, Field

from app.core import storage
from app.core.config import get_settings
from app.core.net import is_public_ip, resolve_host
from app.domains.assessments.service import EngineContext, EngineSpec, register
from app.domains.assets.service import AssetSpec
from app.domains.findings.service import EvidenceInput, FindingInput
from app.integrations.base import ApiError, ConnectorSpec, register_connector
from app.integrations.intel import sources as intel
from app.integrations.scanners import parsers
from app.models import Asset
from app.workers.queue import JobCancelled, PermanentJobError

MAX_OUTPUT = 64 * 1024 * 1024


def run_tool(ctx: EngineContext, argv: list[str], *, timeout: int | None = None, cwd: str | None = None,
             ok_codes: tuple[int, ...] = (0,)) -> bytes:
    """Run an external scanner without a shell, with a timeout, an output cap and cooperative
    cancellation. Returns stdout."""
    timeout = timeout or get_settings().scanner_timeout_seconds
    executable = shutil.which(argv[0])
    if executable is None:
        raise PermanentJobError(f"{argv[0]} is not installed on this worker")
    argv = [executable, *argv[1:]]
    # Minimal environment: the tool's own directory first (some tools are wrappers that call siblings).
    tool_dir = str(Path(executable).resolve().parent)
    env = {"PATH": f"{Path(executable).parent}:{tool_dir}:/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin",
           "HOME": tempfile.gettempdir(), "NO_COLOR": "1", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        proc = subprocess.Popen(argv, stdout=out, stderr=err, stdin=subprocess.DEVNULL, cwd=cwd, env=env)  # noqa: S603
        deadline = time.monotonic() + timeout
        try:
            while proc.poll() is None:
                if time.monotonic() > deadline:
                    proc.kill()
                    raise PermanentJobError(f"{argv[0]} exceeded the {timeout}s time limit")
                try:
                    ctx.checkpoint()
                except JobCancelled:
                    proc.kill()
                    raise
                time.sleep(0.2)
        finally:
            if proc.poll() is None:
                proc.kill()
        out.seek(0)
        err.seek(0)
        stdout, stderr = out.read(MAX_OUTPUT), err.read(8192).decode(errors="replace")
    if proc.returncode not in ok_codes:
        raise PermanentJobError(f"{argv[0]} exited with status {proc.returncode}: {stderr.strip()[-600:]}")
    return stdout


def ingest_parsed(ctx: EngineContext, items, source: str) -> None:
    seen_assets: dict[tuple[str, str], Asset] = {}
    for p in items:
        ctx.checkpoint()
        key = (p.asset.type, p.asset.identifier)
        asset = seen_assets.get(key)
        if asset is None:
            asset = ctx.asset(AssetSpec(type=p.asset.type, identifier=p.asset.identifier, name=p.asset.name,
                                        exposure=p.asset.exposure, attributes=p.asset.attributes))
            seen_assets[key] = asset
            ctx.mark_complete(asset)
        ctx.finding(FindingInput(
            asset=asset, source=source, rule_id=p.rule_id, domain=p.domain, title=p.title, severity=p.severity,
            description=p.description, confidence=p.confidence, remediation=p.remediation, references=p.references,
            cwe=p.cwe, vulnerability_id=p.cve, discriminator=p.discriminator, attributes=p.attributes,
            evidence=[EvidenceInput("scanner_output", f"{source} result for rule {p.rule_id}", p.evidence)] if p.evidence else [],
        ))


# --- Network services (nmap) -------------------------------------------------------------

# port -> (label, severity when internet-exposed, finding domain, guidance)
SENSITIVE_PORTS: dict[int, tuple[str, str, str, str]] = {
    23: ("Telnet", "high", "network", "Disable Telnet; use SSH."),
    445: ("SMB", "high", "network", "Do not expose SMB to untrusted networks."),
    1433: ("Microsoft SQL Server", "high", "network", "Restrict database listeners to application subnets."),
    2375: ("Docker Engine API (unauthenticated)", "critical", "container", "Disable the TCP socket or require mutual TLS."),
    3306: ("MySQL", "high", "network", "Restrict database listeners to application subnets."),
    3389: ("RDP", "high", "network", "Place RDP behind a VPN or gateway with MFA."),
    5432: ("PostgreSQL", "high", "network", "Restrict database listeners to application subnets."),
    5900: ("VNC", "high", "network", "Do not expose VNC; tunnel over SSH or VPN."),
    6379: ("Redis", "high", "network", "Bind Redis to private interfaces and require authentication."),
    6443: ("Kubernetes API server", "medium", "container", "Restrict API server access to trusted networks."),
    8888: ("Jupyter Notebook", "high", "ai_infra", "Require authentication and restrict notebook servers to private networks."),
    9200: ("Elasticsearch", "high", "network", "Enable authentication and restrict network access."),
    10250: ("Kubelet API", "high", "container", "Restrict kubelet access to the control plane."),
    11434: ("Ollama inference API", "high", "ai_infra", "Ollama has no built-in authentication; bind to localhost or front it with an authenticating proxy."),
    27017: ("MongoDB", "high", "network", "Enable authentication and restrict network access."),
    6333: ("Qdrant vector database", "high", "ai_infra", "Enable API-key authentication and restrict network access."),
    19530: ("Milvus vector database", "high", "ai_infra", "Enable authentication and restrict network access."),
    8000: ("HTTP service (commonly vLLM / ChromaDB / app servers)", "info", "network", "Confirm the service is intended to be reachable."),
}
_LOWER = {"critical": "high", "high": "medium", "medium": "low", "low": "info", "info": "info"}


def record_network_services(ctx: EngineContext, hosts: list[parsers.NmapHost], source: str) -> None:
    for host in hosts:
        public = is_public_ip(ipaddress.ip_address(host.address))
        ip_asset = ctx.asset(AssetSpec(type="ip_address", identifier=host.address, exposure="internet" if public else "internal",
                                       attributes={"hostnames": host.hostnames}))
        for port in host.ports:
            label = " ".join(x for x in (port.product, port.version) if x) or port.service or "unknown"
            svc = ctx.asset(AssetSpec(
                type="network_service", identifier=f"{host.address}:{port.port}/{port.protocol}",
                name=f"{port.service or 'service'} on {host.address}:{port.port}", exposure=ip_asset.exposure,
                attributes={"port": port.port, "protocol": port.protocol, "service": port.service, "product": port.product,
                            "version": port.version}))
            ctx.link(ip_asset, svc, "EXPOSES", evidence={"port": port.port, "state": "open"})
            ctx.mark_complete(svc)
            if port.port in SENSITIVE_PORTS:
                name, sev, domain, guidance = SENSITIVE_PORTS[port.port]
                ctx.finding(FindingInput(
                    asset=svc, source=source, rule_id=f"network.exposed.{port.port}", domain=domain,
                    severity=sev if public else _LOWER[sev], confidence="firm", cwe="CWE-284",
                    owasp_llm="LLM10:2025" if domain == "ai_infra" else None,
                    title=f"{name} reachable on {host.address}:{port.port}" + ("" if public else " (internal network)"),
                    description=f"Port {port.port}/{port.protocol} is open and identified as: {label}.",
                    technical_impact="Sensitive service reachable by network attackers; subject to credential attacks and service exploits.",
                    remediation=guidance, reproduction=f"nmap -Pn -p {port.port} {host.address}",
                    evidence=[EvidenceInput("scanner_output", f"Open port {port.port} on {host.address}",
                                            {"port": port.port, "service": port.service, "product": port.product, "version": port.version})],
                ))
        ctx.mark_complete(ip_asset)


_TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:\-]{0,253}(/\d{1,3})?$")


class NmapConfig(BaseModel):
    top_ports: int = Field(default=100, ge=1, le=1000)
    ports: str | None = Field(default=None, pattern=r"^[0-9,\-]{1,200}$", description="Explicit port list, e.g. 22,80,443,8000-8100")
    service_detection: bool = True
    max_rate: int = Field(default=200, ge=1, le=2000, description="Packets per second")


def run_nmap(ctx: EngineContext) -> None:
    config: NmapConfig = ctx.config  # type: ignore[assignment]
    addresses: list[str] = []
    for target in ctx.targets:
        value = target.value.strip()
        if not _TARGET_RE.match(value):
            raise PermanentJobError(f"Invalid scan target {value!r}")
        decision = ctx.scope(value, active=True)
        if "/" in value:
            network = ipaddress.ip_network(value, strict=False)
            if network.num_addresses > 256:
                raise PermanentJobError("CIDR targets larger than /24 are not scanned in one assessment")
            if not decision.allow_private and not is_public_ip(network.network_address):
                raise PermanentJobError(f"{value} is a private range and private targets are not authorised")
            addresses.append(str(network))
        else:
            # Resolve here and scan the validated addresses so nmap never follows a different DNS answer.
            addresses.extend(resolve_host(value, allow_private=decision.allow_private))
    ports = ["-p", config.ports] if config.ports else ["--top-ports", str(config.top_ports)]
    argv = ["nmap", "-sT", "-Pn", "-n", *ports, "--max-rate", str(config.max_rate), "--host-timeout", "300s", "-oX", "-"]
    if config.service_detection:
        argv += ["-sV", "--version-light"]
    argv += ["--", *dict.fromkeys(addresses)]
    if ctx.dry_run:
        ctx.planned("Execute: " + " ".join(argv))
        return
    ctx.job.progress(10, "Running nmap")
    hosts = parsers.parse_nmap_hosts(run_tool(ctx, argv))
    ctx.stats["hosts_up"] = len(hosts)
    record_network_services(ctx, hosts, ctx.source)


class NucleiConfig(BaseModel):
    severities: list[str] = Field(default=["critical", "high", "medium"], max_length=5)
    tags: list[str] = Field(default=[], max_length=20)
    exclude_tags: list[str] = Field(default=["dos", "fuzz", "intrusive"], max_length=20)
    rate_limit: int = Field(default=50, ge=1, le=500)
    templates: str | None = Field(default=None, description="Template file or directory on the worker; default: installed templates")


def run_nuclei(ctx: EngineContext) -> None:
    config: NucleiConfig = ctx.config  # type: ignore[assignment]
    safe = re.compile(r"^[A-Za-z0-9_.\-]+$")
    if not all(safe.match(v) for v in [*config.severities, *config.tags, *config.exclude_tags]):
        raise PermanentJobError("Severities and tags may only contain letters, digits, '.', '_' and '-'")
    urls = []
    for target in ctx.targets:
        decision = ctx.scope(target.value, active=True)
        host = re.sub(r"^https?://", "", target.value).split("/")[0].split(":")[0]
        resolve_host(host, allow_private=decision.allow_private)  # refuse private destinations unless authorised
        urls.append(target.value)
    argv = ["nuclei", "-jsonl", "-silent", "-duc", "-ni", "-rate-limit", str(config.rate_limit), "-timeout", "10",
            "-severity", ",".join(config.severities)]
    if config.tags:
        argv += ["-tags", ",".join(config.tags)]
    if config.exclude_tags:
        argv += ["-exclude-tags", ",".join(config.exclude_tags)]
    if config.templates:
        path = Path(config.templates).resolve()
        if not path.exists():
            raise PermanentJobError(f"Template path {path} does not exist on this worker")
        argv += ["-t", str(path)]
    for url in urls:
        argv += ["-u", url]
    if ctx.dry_run:
        ctx.planned("Execute: " + " ".join(argv))
        return
    ctx.job.progress(10, "Running nuclei")
    output = run_tool(ctx, argv)
    for url in urls:  # every target was fully assessed even when nothing matched
        asset = ctx.asset(AssetSpec(type="website", identifier=parsers._origin(url)))
        ctx.mark_complete(asset)
    if output.strip():
        ingest_parsed(ctx, parsers.parse_nuclei(output), ctx.source)


# --- Path-based scanners -----------------------------------------------------------------

PATH_TOOLS: dict[str, dict] = {
    "trivy": {"name": "Trivy filesystem scan", "module": "supply_chain", "parser": "trivy", "ok": (0,),
              "argv": lambda p: ["trivy", "fs", "--quiet", "--format", "json", "--scanners", "vuln,misconfig,secret", p],
              "description": "Vulnerable dependencies, IaC misconfigurations and secrets in a source tree."},
    "grype": {"name": "Grype dependency scan", "module": "supply_chain", "parser": "grype", "ok": (0,),
              "argv": lambda p: ["grype", f"dir:{p}", "-o", "json", "-q"],
              "description": "Vulnerable packages in a source tree."},
    "semgrep": {"name": "Semgrep static analysis", "module": "web_api", "parser": "semgrep", "ok": (0, 1),
                "argv": lambda p: ["semgrep", "scan", "--config", "p/default", "--json", "--quiet", "--metrics", "off", p],
                "description": "Static analysis of application source code."},
    "gitleaks": {"name": "Gitleaks secret scan", "module": "supply_chain", "parser": "gitleaks", "ok": (0, 1),
                 "argv": lambda p: ["gitleaks", "dir", p, "--report-format", "json", "--report-path", "/dev/stdout",
                                    "--no-banner", "--redact", "--exit-code", "0"],
                 "description": "Hard-coded credentials in a source tree (values are redacted by the tool)."},
    "checkov": {"name": "Checkov IaC scan", "module": "supply_chain", "parser": "checkov", "ok": (0, 1),
                "argv": lambda p: ["checkov", "-d", p, "-o", "json", "--quiet", "--compact"],
                "description": "Terraform, CloudFormation, Kubernetes and Dockerfile misconfigurations."},
}


def _run_path_tool(tool: str):
    spec = PATH_TOOLS[tool]

    def run(ctx: EngineContext) -> None:
        for target in ctx.targets:
            ctx.scope(target.value, active=False)
            path = str(Path(target.value).resolve())
            argv = spec["argv"](".")  # run inside the tree so reported file paths are repository-relative
            if ctx.dry_run:
                ctx.planned(f"Execute in {path}: " + " ".join(argv))
                continue
            ctx.job.progress(10, f"Running {tool} on {path}")
            output = run_tool(ctx, argv, ok_codes=spec["ok"], cwd=path)
            repo = ctx.asset(AssetSpec(type="repository", identifier=path, name=Path(path).name))
            ctx.mark_complete(repo)
            if output.strip():
                ingest_parsed(ctx, parsers.PARSERS[spec["parser"]](output, path), ctx.source)

    return run


# --- Dependency analysis (OSV) -----------------------------------------------------------

AI_PACKAGES = {
    "openai", "anthropic", "google-generativeai", "google-genai", "langchain", "langchain-core", "langchain-community",
    "llama-index", "llama-index-core", "semantic-kernel", "autogen", "pyautogen", "autogen-agentchat", "crewai",
    "transformers", "torch", "tensorflow", "huggingface-hub", "vllm", "ollama", "mcp", "fastmcp", "chromadb",
    "pinecone", "pinecone-client", "qdrant-client", "weaviate-client", "pymilvus", "litellm", "mlflow", "gradio",
    "@anthropic-ai/sdk", "@langchain/core", "@modelcontextprotocol/sdk", "ai", "llamaindex", "onnx", "keras",
    "sentence-transformers", "langgraph", "haystack-ai", "bentoml", "ray", "triton", "boto3-bedrock",
}
_OSV_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}


def analyse_components(ctx: EngineContext, parent: Asset, components: list[parsers.SbomComponent], source: str) -> dict:
    """Record packages and query OSV for known vulnerabilities in each (name, version)."""
    usable = [c for c in components if c.version and (c.ecosystem or (c.purl or "").startswith("pkg:"))]
    skipped = len(components) - len(usable)
    packages = [{"name": c.name, "version": c.version, "ecosystem": c.ecosystem, "purl": c.purl} for c in usable]
    try:
        results = intel.osv_query(packages) if packages else []
    except ApiError as exc:
        raise RuntimeError(f"OSV query failed ({exc.error_class}): {exc}") from exc
    ctx.stats["requests"] += 1 + len(packages) // 500
    details: dict[str, dict] = {}
    vulnerable = 0
    for component, osv_ids in zip(usable, results, strict=False):
        if not osv_ids:
            continue
        vulnerable += 1
        ai_related = component.name.lower() in AI_PACKAGES
        pkg = ctx.asset(AssetSpec(
            type="package", identifier=component.purl or f"pkg:{(component.ecosystem or 'generic').lower()}/{component.name}@{component.version}",
            name=f"{component.name} {component.version}",
            attributes={"ecosystem": component.ecosystem, "version": component.version, "ai_related": ai_related}))
        ctx.link(parent, pkg, "DEPENDS_ON", evidence={"source": source})
        for osv_id in osv_ids[:40]:
            ctx.checkpoint()
            if osv_id not in details:
                details[osv_id] = intel.osv_get(osv_id)
                ctx.stats["requests"] += 1
            osv = details[osv_id]
            vuln = intel.osv_to_vulnerability(ctx.db, osv)
            label = _OSV_SEVERITY.get(str((osv.get("database_specific") or {}).get("severity", "")).upper())
            fixed = ", ".join(vuln.fixed_versions[:3])
            ctx.finding(FindingInput(
                asset=pkg, source=source, rule_id=vuln.external_id, domain="supply_chain", severity=label or "medium",
                confidence="confirmed", vulnerability_id=vuln.external_id,
                title=f"{vuln.external_id}: {component.name} {component.version}" + (f" - {osv['summary']}" if osv.get("summary") else ""),
                description=(osv.get("details") or "")[:6000],
                remediation=f"Upgrade {component.name} to a fixed version ({fixed})." if fixed else "No fixed version is published; review the advisory for mitigations.",
                references=[r.get("url") for r in (osv.get("references") or [])[:8] if r.get("url")],
                attributes={"package": component.name, "installed_version": component.version, "ecosystem": component.ecosystem,
                            "osv_id": osv_id, "severity_source": "advisory" if label else "default (advisory has no severity label)",
                            "used_by": parent.name},
                evidence=[EvidenceInput("scanner_output", f"OSV match for {component.name}@{component.version}",
                                        {"osv_id": osv_id, "aliases": osv.get("aliases"), "package": component.name,
                                         "version": component.version, "queried": "https://api.osv.dev/v1/querybatch"})],
            ))
        ctx.mark_complete(pkg)
    return {"components": len(components), "queried": len(usable), "vulnerable_components": vulnerable,
            "skipped_no_version_or_ecosystem": skipped}


# --- Result import -----------------------------------------------------------------------

class ImportConfig(BaseModel):
    format: str
    storage_key: str
    sha256: str
    target: str | None = None
    filename: str = ""
    fail_on: str = "none"
    ci: dict | None = None


def run_import(ctx: EngineContext) -> None:
    config: ImportConfig = ctx.config  # type: ignore[assignment]
    if ctx.dry_run:
        ctx.planned(f"Parse stored {config.format} report {config.sha256[:12]}")
        return
    data = storage.read_for_org(ctx.assessment.organization_id, config.storage_key)
    source = f"import:{config.format}"
    try:
        if config.format == "nmap":
            hosts = parsers.parse_nmap_hosts(data)
            ctx.stats["hosts_up"] = len(hosts)
            record_network_services(ctx, hosts, source)
        elif config.format == "aictem":
            from app.engines.inventory_import import ingest

            ingest(ctx, data, config.target, source)
        elif config.format == "sbom":
            fmt, subject, components = parsers.parse_sbom(data)
            identifier = config.target or subject
            if not identifier:
                raise PermanentJobError("The SBOM does not name its subject; supply the 'target' field")
            parent = ctx.asset(AssetSpec(type="repository", identifier=identifier, attributes={"sbom_format": fmt}))
            ctx.stats.update(analyse_components(ctx, parent, components, source))
        else:
            ingest_parsed(ctx, parsers.PARSERS[config.format](data, config.target), source)
    except parsers.ReportFormatError as exc:
        raise PermanentJobError(str(exc)) from exc
    if config.ci:  # record which build last reported on each asset
        from app.models import Asset as AssetModel

        build = {k: config.ci.get(k) for k in ("provider", "repository", "branch", "commit", "pipeline_url") if config.ci.get(k)}
        build["at"] = ctx.run.created_at.isoformat() if ctx.run.created_at else None
        for asset_id in ctx.touched_assets:
            asset = ctx.db.get(AssetModel, asset_id)
            if asset is not None:
                asset.attributes = {**(asset.attributes or {}), "last_ci_build": build}
    ctx.db.flush()
    from app.domains.ci.service import evaluate_gate

    ctx.stats["gate"] = evaluate_gate(ctx.db, ctx.run.id, config.fail_on)


register(EngineSpec(kind="scanner_import", name="Scanner result import", module="vulnerabilities", run=run_import,
                    description="Parses an uploaded scanner report and normalises its findings.", config_model=ImportConfig))
register(EngineSpec(kind="nmap_scan", permission="discovery:run", name="Network service discovery (Nmap)", module="attack_surface", run=run_nmap,
                    description="TCP connect scan with optional service detection; flags exposed administrative, database and AI services.",
                    config_model=NmapConfig, target_kinds=("domain", "cidr"), active=True, requires_tool="nmap"))
register(EngineSpec(kind="nuclei_scan", name="Template-based vulnerability scan (Nuclei)", module="vulnerabilities", run=run_nuclei,
                    description="Runs Nuclei templates against authorised URLs. DoS, fuzzing and intrusive templates are excluded by default.",
                    config_model=NucleiConfig, target_kinds=("url",), active=True, requires_tool="nuclei", version_args=("-version",)))
for _tool, _spec in PATH_TOOLS.items():
    register(EngineSpec(kind=f"{_tool}_scan", name=_spec["name"], module=_spec["module"], run=_run_path_tool(_tool),
                        description=_spec["description"], target_kinds=("path",), requires_tool=_tool))

_SCANNERS = [
    ("nmap", "Nmap", "tool", "TCP service discovery run by workers against authorized networks. Nmap XML reports can also be uploaded."),
    ("nuclei", "Nuclei", "tool", "Template-based vulnerability scanning run by workers against authorized URLs. JSON/JSONL exports can also be uploaded."),
    ("trivy", "Trivy", "tool", "Dependency, IaC and secret scanning of source trees run by workers. JSON reports, including container image scans, can be uploaded."),
    ("grype", "Grype", "tool", "Package vulnerability scanning of source trees run by workers. JSON reports can be uploaded."),
    ("semgrep", "Semgrep", "tool", "Static analysis of application source run by workers. JSON reports can be uploaded."),
    ("gitleaks", "Gitleaks", "tool", "Secret detection in source trees run by workers; secret values are never stored. JSON reports can be uploaded."),
    ("checkov", "Checkov", "tool", "Terraform, CloudFormation, Kubernetes and Dockerfile checks run by workers. JSON reports can be uploaded."),
    ("zap", "OWASP ZAP", "upload", "Upload ZAP traditional JSON reports from baseline, full or API scans."),
    ("prowler", "Prowler", "upload", "Upload Prowler OCSF JSON output. Covers AWS, Azure, Google Cloud and Kubernetes posture checks."),
    ("sarif", "SARIF", "upload", "Upload SARIF 2.1.0 results from any static or dynamic analysis tool."),
    ("sbom", "Software bill of materials", "upload", "Upload CycloneDX or SPDX JSON; components are inventoried and checked against OSV."),
    ("aictem", "aictem CLI inventory", "upload", "Upload `aictem discover --format json` reports: repository, dependency, container, cloud, CI and AI "
             "assets (providers, frameworks, agents, RAG, MCP, models) with relationships and findings. Package versions are checked against OSV."),
]
for _key, _name, _mode, _desc in _SCANNERS:
    register_connector(ConnectorSpec(key=_key, name=_name, category="scanner", description=_desc, mode=_mode,
                                     import_format=_key, configurable=False))

__all__ = ["analyse_components", "ingest_parsed", "record_network_services", "run_tool", "shutil"]
