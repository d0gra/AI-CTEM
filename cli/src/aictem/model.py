"""Inventory data model: assets, relationships and findings, merged as detectors report them.

Asset types, relationship types and finding domains match the CTEM platform's, so a report can be
uploaded unchanged (`aictem discover --upload`, or the `aictem` report format).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

SCHEMA = "aictem-inventory/1"

ASSET_TYPES = {
    "domain", "subdomain", "ip_address", "dns_record", "website", "http_service", "api", "api_endpoint", "certificate",
    "cloud_account", "cloud_resource", "load_balancer", "storage", "database", "network_service", "host", "container_image",
    "k8s_resource", "repository", "package", "identity", "ai_application", "llm_endpoint", "ai_agent", "mcp_server",
    "mcp_client", "ai_model", "vector_database", "rag_application", "ai_framework", "ai_provider", "model_registry", "data_source",
}
AI_ASSET_TYPES = {
    "ai_application", "llm_endpoint", "ai_agent", "mcp_server", "mcp_client", "ai_model", "vector_database", "rag_application",
    "ai_framework", "ai_provider", "model_registry",
}
RELATIONSHIP_TYPES = {
    "CONNECTS_TO", "RUNS_ON", "EXPOSES", "AUTHENTICATES_TO", "HAS_PERMISSION", "DEPENDS_ON", "TRUSTS", "CONTAINS",
    "RETRIEVES_FROM", "INVOKES_TOOL", "PROCESSES_DATA", "AFFECTED_BY", "RESOLVES_TO", "SECURED_BY", "CAN_ASSUME",
}
FINDING_DOMAINS = {
    "attack_surface", "vulnerability", "web", "api", "cloud", "identity", "network", "container", "iac", "supply_chain",
    "secrets", "ai_llm", "ai_rag", "ai_agent", "ai_mcp", "ai_model", "ai_infra", "shadow_ai", "policy",
}
SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {s: i for i, s in enumerate(reversed(SEVERITIES))}  # info=0 ... critical=4
MAX_LOCATIONS = 25


@dataclass
class Location:
    file: str
    line: int | None = None
    method: str = ""  # dependency | import | config | endpoint | secret | file | container | iac | code

    def text(self) -> str:
        return f"{self.file}:{self.line}" if self.line else self.file


@dataclass
class Asset:
    type: str
    identifier: str
    name: str
    attributes: dict = field(default_factory=dict)
    ai: dict | None = None
    locations: list[Location] = field(default_factory=list)

    @property
    def ref(self) -> str:
        return f"{self.type}:{self.identifier}"


@dataclass
class Relationship:
    source: str
    target: str
    type: str
    evidence: dict = field(default_factory=dict)


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    domain: str
    asset: str  # asset ref
    description: str = ""
    remediation: str = ""
    confidence: str = "firm"
    file: str | None = None
    line: int | None = None
    cwe: str | None = None
    owasp_llm: str | None = None
    atlas_technique: str | None = None
    nist_ai_rmf: str | None = None
    discriminator: str = ""
    evidence: dict = field(default_factory=dict)

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.rule_id, self.asset, self.discriminator)


class Inventory:
    def __init__(self) -> None:
        self.assets: dict[str, Asset] = {}
        self.relationships: dict[tuple[str, str, str], Relationship] = {}
        self.findings: dict[tuple[str, str, str], Finding] = {}

    def add(self, type: str, identifier: str, name: str | None = None, *, attributes: dict | None = None, ai: dict | None = None,
            location: Location | None = None) -> Asset:
        """Create an asset or merge into the existing one with the same (type, identifier)."""
        assert type in ASSET_TYPES, type
        identifier = identifier[:1000]
        ref = f"{type}:{identifier}"
        asset = self.assets.get(ref)
        if asset is None:
            asset = self.assets[ref] = Asset(type=type, identifier=identifier, name=(name or identifier)[:512])
        for key, value in (attributes or {}).items():
            if isinstance(value, list) and isinstance(asset.attributes.get(key), list):
                merged = asset.attributes[key] + [v for v in value if v not in asset.attributes[key]]
                asset.attributes[key] = merged[:200]
            elif value is not None:
                asset.attributes.setdefault(key, value)
        if ai:
            asset.ai = {**(asset.ai or {}), **{k: v for k, v in ai.items() if v is not None}}
        if location and len(asset.locations) < MAX_LOCATIONS and location not in asset.locations:
            asset.locations.append(location)
        return asset

    def link(self, source: Asset, target: Asset, type: str, **evidence) -> None:
        assert type in RELATIONSHIP_TYPES, type
        if source.ref != target.ref:
            self.relationships.setdefault((source.ref, target.ref, type), Relationship(source.ref, target.ref, type, evidence))

    def finding(self, finding: Finding) -> Finding:
        assert finding.severity in SEVERITIES and finding.domain in FINDING_DOMAINS, (finding.severity, finding.domain)
        return self.findings.setdefault(finding.key, finding)

    def of_type(self, *types: str) -> list[Asset]:
        return [a for a in self.assets.values() if a.type in types]

    def to_dict(self) -> dict:
        return {
            "assets": [{**{k: v for k, v in asdict(a).items() if k != "locations"}, "ref": a.ref,
                        "locations": [{k: v for k, v in asdict(loc).items() if v} for loc in a.locations]}
                       for a in sorted(self.assets.values(), key=lambda a: (a.type, a.identifier))],
            "relationships": [asdict(r) for r in sorted(self.relationships.values(), key=lambda r: (r.type, r.source, r.target))],
            "findings": [{k: v for k, v in asdict(f).items() if v not in (None, "", {})}
                         for f in sorted(self.findings.values(), key=lambda f: (-SEVERITY_RANK[f.severity], f.rule_id, f.asset))],
        }
