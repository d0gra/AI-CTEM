"""Parsers that normalise third-party scanner output into platform findings.

Each parser accepts the raw report bytes and yields `ParsedFinding` records. Parsers are pure
(no I/O) and tolerant of missing optional fields, but raise `ReportFormatError` when the
document is not the expected format, so a wrong upload fails loudly instead of importing
nothing.
"""

import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from defusedxml import ElementTree as SafeET


class ReportFormatError(ValueError):
    pass


@dataclass
class ParsedAsset:
    type: str
    identifier: str
    name: str | None = None
    exposure: str | None = None
    attributes: dict = field(default_factory=dict)


@dataclass
class ParsedFinding:
    asset: ParsedAsset
    rule_id: str
    title: str
    severity: str
    domain: str
    description: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    cve: str | None = None
    cwe: str | None = None
    confidence: str = "firm"
    discriminator: str = ""
    evidence: dict = field(default_factory=dict)
    attributes: dict = field(default_factory=dict)


_SEVERITY = {
    "critical": "critical", "high": "high", "medium": "medium", "moderate": "medium", "low": "low",
    "info": "info", "informational": "info", "negligible": "info", "unknown": "low", "none": "info",
    "error": "high", "warning": "medium", "note": "low",
}


def severity(value) -> str:
    return _SEVERITY.get(str(value or "").strip().lower(), "low")


def _load_json(data: bytes):
    try:
        return json.loads(data)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ReportFormatError(f"Report is not valid JSON: {exc}") from exc


def _origin(url: str) -> str:
    parts = urlsplit(url if "://" in url else f"//{url}")
    if parts.scheme in ("http", "https") and parts.netloc:
        return f"{parts.scheme}://{parts.netloc}"
    return parts.netloc or url


def _first_cve(values) -> str | None:
    for v in values or []:
        if isinstance(v, str) and v.upper().startswith("CVE-"):
            return v.upper()
    return None


def _cwe(value) -> str | None:
    if isinstance(value, list):
        value = value[0] if value else None
    if not value:
        return None
    text = str(value).upper().split(":")[0].strip()
    return text if text.startswith("CWE-") else (f"CWE-{text}" if text.isdigit() and text != "0" else None)


def _default_asset(target: str | None, fallback: str, type_: str = "repository") -> ParsedAsset:
    identifier = (target or fallback or "").strip()
    if not identifier:
        raise ReportFormatError("The report does not name its target; supply the 'target' field")
    return ParsedAsset(type_, identifier)


def parse_nuclei(data: bytes, target: str | None = None) -> Iterator[ParsedFinding]:
    text = data.decode("utf-8", errors="replace").strip()
    records = _load_json(data) if text.startswith("[") else [json.loads(line) for line in text.splitlines() if line.strip().startswith("{")]
    if not isinstance(records, list) or (records and "template-id" not in records[0]):
        raise ReportFormatError("Not a nuclei JSON/JSONL export (missing 'template-id')")
    for r in records:
        info = r.get("info") or {}
        classification = info.get("classification") or {}
        host = r.get("matched-at") or r.get("host") or target or ""
        is_http = r.get("type") in ("http", "headless") or str(host).startswith("http")
        asset = ParsedAsset("website" if is_http else "host", _origin(host) if is_http else str(host).split(":")[0])
        refs = info.get("reference") or []
        yield ParsedFinding(
            asset=asset, rule_id=str(r["template-id"]), title=info.get("name") or r["template-id"],
            severity=severity(info.get("severity")), domain="web" if is_http else "network",
            description=info.get("description") or "", remediation=info.get("remediation") or "",
            references=[refs] if isinstance(refs, str) else list(refs)[:15], cve=_first_cve(classification.get("cve-id")),
            cwe=_cwe(classification.get("cwe-id")), confidence="confirmed" if r.get("matcher-status", True) else "tentative",
            discriminator=str(r.get("matched-at") or "") + str(r.get("matcher-name") or ""),
            evidence={"matched_at": r.get("matched-at"), "matcher": r.get("matcher-name"),
                      "extracted": (r.get("extracted-results") or [])[:10], "curl": r.get("curl-command"),
                      "timestamp": r.get("timestamp")},
        )


def parse_trivy(data: bytes, target: str | None = None) -> Iterator[ParsedFinding]:
    doc = _load_json(data)
    if not isinstance(doc, dict) or "Results" not in doc and "ArtifactName" not in doc:
        raise ReportFormatError("Not a Trivy JSON report (missing 'Results')")
    artifact_type = doc.get("ArtifactType", "")
    asset_type = "container_image" if artifact_type == "container_image" else "repository"
    asset = _default_asset(target, doc.get("ArtifactName", ""), asset_type)
    for result in doc.get("Results") or []:
        location = result.get("Target", "")
        for v in result.get("Vulnerabilities") or []:
            vid = v.get("VulnerabilityID", "")
            yield ParsedFinding(
                asset=asset, rule_id=vid, severity=severity(v.get("Severity")),
                domain="container" if asset_type == "container_image" else "supply_chain",
                title=f"{vid}: {v.get('PkgName')} {v.get('InstalledVersion')}" + (f" - {v['Title']}" if v.get("Title") else ""),
                description=v.get("Description") or "", cve=vid if vid.upper().startswith("CVE-") else None,
                cwe=_cwe(v.get("CweIDs")), references=[u for u in [v.get("PrimaryURL")] if u], confidence="confirmed",
                remediation=f"Upgrade {v.get('PkgName')} to {v['FixedVersion']}." if v.get("FixedVersion") else "No fixed version is available; apply vendor mitigations.",
                discriminator=f"{location}|{v.get('PkgName')}@{v.get('InstalledVersion')}",
                attributes={"package": v.get("PkgName"), "installed_version": v.get("InstalledVersion"),
                            "fixed_version": v.get("FixedVersion"), "location": location, "vulnerability_id": vid},
                evidence={"target": location, "package": v.get("PkgName"), "installed": v.get("InstalledVersion"),
                          "fixed": v.get("FixedVersion")},
            )
        for m in result.get("Misconfigurations") or []:
            if m.get("Status") not in (None, "FAIL"):
                continue
            cause = m.get("CauseMetadata") or {}
            yield ParsedFinding(
                asset=asset, rule_id=m.get("ID", "trivy-misconfig"), title=m.get("Title") or m.get("ID", ""),
                severity=severity(m.get("Severity")), domain="iac", description=m.get("Description") or m.get("Message") or "",
                remediation=m.get("Resolution") or "", references=(m.get("References") or [])[:10], confidence="confirmed",
                discriminator=f"{location}:{cause.get('StartLine', '')}:{cause.get('Resource', '')}",
                evidence={"file": location, "resource": cause.get("Resource"), "lines": [cause.get("StartLine"), cause.get("EndLine")],
                          "message": m.get("Message")},
            )
        for s in result.get("Secrets") or []:
            yield ParsedFinding(
                asset=asset, rule_id=s.get("RuleID", "secret"), title=f"Secret detected: {s.get('Title') or s.get('RuleID')}",
                severity=severity(s.get("Severity") or "high"), domain="secrets", cwe="CWE-798",
                description=f"A credential matching rule {s.get('RuleID')} was found in {location}.",
                remediation="Revoke and rotate the credential, then remove it from the repository history.",
                discriminator=f"{location}:{s.get('StartLine')}", evidence={"file": location, "line": s.get("StartLine")},
            )


def parse_grype(data: bytes, target: str | None = None) -> Iterator[ParsedFinding]:
    doc = _load_json(data)
    if not isinstance(doc, dict) or "matches" not in doc:
        raise ReportFormatError("Not a Grype JSON report (missing 'matches')")
    source = doc.get("source") or {}
    src_target = source.get("target")
    name = src_target.get("userInput") if isinstance(src_target, dict) else src_target
    asset = _default_asset(target, name or "", "container_image" if source.get("type") == "image" else "repository")
    for m in doc["matches"]:
        v, a = m.get("vulnerability") or {}, m.get("artifact") or {}
        vid = v.get("id", "")
        related = [r.get("id") for r in m.get("relatedVulnerabilities") or []]
        fixed = ((v.get("fix") or {}).get("versions") or [None])[0]
        yield ParsedFinding(
            asset=asset, rule_id=vid, title=f"{vid}: {a.get('name')} {a.get('version')}", severity=severity(v.get("severity")),
            domain="container" if asset.type == "container_image" else "supply_chain", description=v.get("description") or "",
            cve=_first_cve([vid, *related]), references=(v.get("urls") or [])[:10], confidence="confirmed",
            remediation=f"Upgrade {a.get('name')} to {fixed}." if fixed else "No fixed version is available.",
            discriminator=f"{a.get('name')}@{a.get('version')}",
            attributes={"package": a.get("name"), "installed_version": a.get("version"), "fixed_version": fixed,
                        "purl": a.get("purl"), "vulnerability_id": vid},
            evidence={"package": a.get("name"), "version": a.get("version"), "type": a.get("type"),
                      "locations": [loc.get("path") for loc in (a.get("locations") or [])[:5]]},
        )


def parse_semgrep(data: bytes, target: str | None = None) -> Iterator[ParsedFinding]:
    doc = _load_json(data)
    if not isinstance(doc, dict) or "results" not in doc:
        raise ReportFormatError("Not a Semgrep JSON report (missing 'results')")
    asset = _default_asset(target, "")
    for r in doc["results"]:
        extra = r.get("extra") or {}
        meta = extra.get("metadata") or {}
        line = (r.get("start") or {}).get("line")
        confidence = {"HIGH": "firm", "MEDIUM": "firm", "LOW": "tentative"}.get(str(meta.get("confidence", "")).upper(), "firm")
        refs = meta.get("references") or []
        yield ParsedFinding(
            asset=asset, rule_id=r.get("check_id", "semgrep"), severity=severity(extra.get("severity")), domain="web",
            title=f"{r.get('check_id', '').split('.')[-1]} in {r.get('path')}:{line}", description=extra.get("message") or "",
            cwe=_cwe(meta.get("cwe")), references=[refs] if isinstance(refs, str) else list(refs)[:10], confidence=confidence,
            remediation=extra.get("fix") and f"Suggested fix: {extra['fix']}" or "Review the flagged code and apply the rule's guidance.",
            discriminator=f"{r.get('path')}:{line}", evidence={"file": r.get("path"), "line": line, "owasp": meta.get("owasp")},
        )


def parse_gitleaks(data: bytes, target: str | None = None) -> Iterator[ParsedFinding]:
    doc = _load_json(data)
    if not isinstance(doc, list) or (doc and "RuleID" not in doc[0]):
        raise ReportFormatError("Not a Gitleaks JSON report (expected an array of leaks with 'RuleID')")
    asset = _default_asset(target, "")
    for leak in doc:
        yield ParsedFinding(
            asset=asset, rule_id=leak.get("RuleID", "secret"), severity="high", domain="secrets", cwe="CWE-798",
            title=f"Secret detected: {leak.get('Description') or leak.get('RuleID')} in {leak.get('File')}",
            description="A hard-coded credential was detected in source control. The secret value is not stored by this platform.",
            remediation="Revoke and rotate the credential, purge it from history, and add a pre-commit secret scan.",
            discriminator=leak.get("Fingerprint") or f"{leak.get('File')}:{leak.get('StartLine')}",
            evidence={"file": leak.get("File"), "line": leak.get("StartLine"), "commit": leak.get("Commit"),
                      "author": leak.get("Author"), "date": leak.get("Date"), "entropy": leak.get("Entropy")},
        )


def parse_checkov(data: bytes, target: str | None = None) -> Iterator[ParsedFinding]:
    doc = _load_json(data)
    reports = doc if isinstance(doc, list) else [doc]
    if not all(isinstance(r, dict) and "results" in r for r in reports):
        raise ReportFormatError("Not a Checkov JSON report (missing 'results')")
    asset = _default_asset(target, "")
    for report in reports:
        for c in (report.get("results") or {}).get("failed_checks") or []:
            yield ParsedFinding(
                asset=asset, rule_id=c.get("check_id", "checkov"), title=f"{c.get('check_name')} ({c.get('resource')})",
                severity=severity(c.get("severity") or "medium"), domain="iac", confidence="confirmed",
                description=f"Infrastructure-as-code check {c.get('check_id')} failed for {c.get('resource')}.",
                remediation=c.get("guideline") and f"See {c['guideline']}" or "Apply the control described by the check.",
                references=[c["guideline"]] if c.get("guideline") else [],
                discriminator=f"{c.get('file_path')}:{c.get('resource')}",
                evidence={"file": c.get("file_path"), "lines": c.get("file_line_range"), "resource": c.get("resource"),
                          "framework": report.get("check_type")},
            )


def parse_zap(data: bytes, target: str | None = None) -> Iterator[ParsedFinding]:
    doc = _load_json(data)
    if not isinstance(doc, dict) or "site" not in doc:
        raise ReportFormatError("Not an OWASP ZAP JSON report (missing 'site')")
    risk = {"3": "high", "2": "medium", "1": "low", "0": "info"}
    conf = {"4": "confirmed", "3": "firm", "2": "firm", "1": "tentative", "0": "tentative"}
    sites = doc["site"] if isinstance(doc["site"], list) else [doc["site"]]
    for site in sites:
        asset = ParsedAsset("website", _origin(site.get("@name", target or "")))
        for alert in site.get("alerts") or []:
            instances = alert.get("instances") or []
            yield ParsedFinding(
                asset=asset, rule_id=f"zap-{alert.get('pluginid')}", title=alert.get("alert") or alert.get("name", ""),
                severity=risk.get(str(alert.get("riskcode")), "low"), confidence=conf.get(str(alert.get("confidence")), "firm"),
                domain="web", description=_strip_tags(alert.get("desc", "")), remediation=_strip_tags(alert.get("solution", "")),
                references=[u for u in _strip_tags(alert.get("reference", "")).split() if u.startswith("http")][:10],
                cwe=_cwe(alert.get("cweid")),
                evidence={"instances": [{"uri": i.get("uri"), "method": i.get("method"), "param": i.get("param"),
                                         "evidence": (i.get("evidence") or "")[:200]} for i in instances[:10]],
                          "count": alert.get("count")},
            )


def _strip_tags(text: str) -> str:
    import re

    return re.sub(r"<[^>]+>", " ", text or "").strip()


_PROWLER_TYPES = {"bucket": "storage", "s3": "storage", "storage": "storage", "rds": "database", "sql": "database",
                  "user": "identity", "role": "identity", "iam": "identity", "serviceaccount": "identity"}


def parse_prowler(data: bytes, target: str | None = None) -> Iterator[ParsedFinding]:
    """Prowler OCSF JSON output (v4+), covering AWS, Azure, GCP and Kubernetes."""
    doc = _load_json(data)
    if not isinstance(doc, list) or (doc and "finding_info" not in doc[0]):
        raise ReportFormatError("Not a Prowler OCSF JSON report (expected an array with 'finding_info')")
    for r in doc:
        if str(r.get("status_code", "")).upper() != "FAIL":
            continue
        info, cloud = r.get("finding_info") or {}, r.get("cloud") or {}
        resource = (r.get("resources") or [{}])[0]
        provider = (cloud.get("provider") or "cloud").lower()
        rtype = str(resource.get("type") or "").lower()
        asset_type = next((v for k, v in _PROWLER_TYPES.items() if k in rtype), "cloud_resource")
        identifier = resource.get("uid") or resource.get("name") or (cloud.get("account") or {}).get("uid") or target or ""
        if not identifier:
            continue
        check = (r.get("metadata") or {}).get("event_code") or info.get("uid", "prowler")
        remediation = r.get("remediation") or {}
        yield ParsedFinding(
            asset=ParsedAsset(asset_type, identifier, name=resource.get("name") or identifier,
                              attributes={"provider": provider, "region": resource.get("region"),
                                          "account": (cloud.get("account") or {}).get("uid"), "resource_type": resource.get("type")}),
            rule_id=f"prowler.{provider}.{check}", title=info.get("title") or check, severity=severity(r.get("severity")),
            domain="identity" if asset_type == "identity" else "cloud", description=info.get("desc") or r.get("status_detail") or "",
            remediation=remediation.get("desc") or "", references=(remediation.get("references") or [])[:10],
            confidence="confirmed", evidence={"status_detail": r.get("status_detail"), "region": resource.get("region"),
                                              "compliance": (r.get("unmapped") or {}).get("compliance")},
        )


def parse_sarif(data: bytes, target: str | None = None) -> Iterator[ParsedFinding]:
    doc = _load_json(data)
    if not isinstance(doc, dict) or "runs" not in doc:
        raise ReportFormatError("Not a SARIF document (missing 'runs')")
    asset = _default_asset(target, "")
    for run in doc["runs"]:
        tool = ((run.get("tool") or {}).get("driver") or {})
        rules = {r.get("id"): r for r in tool.get("rules") or []}
        for result in run.get("results") or []:
            rule = rules.get(result.get("ruleId"), {})
            loc = ((result.get("locations") or [{}])[0].get("physicalLocation") or {})
            file_, line = (loc.get("artifactLocation") or {}).get("uri"), (loc.get("region") or {}).get("startLine")
            level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level") or "warning"
            yield ParsedFinding(
                asset=asset, rule_id=f"{tool.get('name', 'sarif')}.{result.get('ruleId')}", severity=severity(level),
                domain="web", title=(rule.get("shortDescription") or {}).get("text") or (result.get("message") or {}).get("text", "")[:200],
                description=(result.get("message") or {}).get("text", ""), remediation=(rule.get("help") or {}).get("text", ""),
                references=[rule["helpUri"]] if rule.get("helpUri") else [], discriminator=f"{file_}:{line}",
                evidence={"file": file_, "line": line, "tool": tool.get("name"), "tool_version": tool.get("version")},
            )


@dataclass
class NmapPort:
    port: int
    protocol: str
    service: str
    product: str
    version: str


@dataclass
class NmapHost:
    address: str
    hostnames: list[str]
    ports: list[NmapPort]


def parse_nmap_hosts(data: bytes) -> list[NmapHost]:
    try:
        root = SafeET.fromstring(data)
    except Exception as exc:
        raise ReportFormatError(f"Not valid Nmap XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise ReportFormatError("Not an Nmap XML report (root element is not 'nmaprun')")
    hosts = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        address = next((a.get("addr") for a in host.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")), None)
        if not address:
            continue
        ports = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            ports.append(NmapPort(int(port.get("portid", "0")), port.get("protocol", "tcp"),
                                  (svc.get("name") if svc is not None else "") or "",
                                  (svc.get("product") if svc is not None else "") or "",
                                  (svc.get("version") if svc is not None else "") or ""))
        hosts.append(NmapHost(address, [h.get("name", "") for h in host.findall("hostnames/hostname")], ports))
    return hosts


@dataclass
class SbomComponent:
    name: str
    version: str
    purl: str | None
    ecosystem: str | None


_PURL_ECOSYSTEMS = {"pypi": "PyPI", "npm": "npm", "maven": "Maven", "golang": "Go", "cargo": "crates.io",
                    "gem": "RubyGems", "nuget": "NuGet", "composer": "Packagist"}


def _ecosystem(purl: str | None) -> str | None:
    if not purl or not purl.startswith("pkg:"):
        return None
    return _PURL_ECOSYSTEMS.get(purl[4:].split("/", 1)[0])


def parse_sbom(data: bytes) -> tuple[str, str | None, list[SbomComponent]]:
    """Parse a CycloneDX or SPDX JSON SBOM. Returns (format, subject name, components)."""
    doc = _load_json(data)
    if isinstance(doc, dict) and doc.get("bomFormat") == "CycloneDX":
        subject = ((doc.get("metadata") or {}).get("component") or {}).get("name")
        comps = [SbomComponent(c.get("name", ""), str(c.get("version", "")), c.get("purl"), _ecosystem(c.get("purl")))
                 for c in doc.get("components") or [] if c.get("name")]
        return "cyclonedx", subject, comps
    if isinstance(doc, dict) and str(doc.get("spdxVersion", "")).startswith("SPDX-"):
        comps = []
        for p in doc.get("packages") or []:
            purl = next((r.get("referenceLocator") for r in p.get("externalRefs") or [] if r.get("referenceType") == "purl"), None)
            if p.get("name"):
                comps.append(SbomComponent(p["name"], str(p.get("versionInfo", "")), purl, _ecosystem(purl)))
        return "spdx", doc.get("name"), comps
    raise ReportFormatError("Not a CycloneDX or SPDX JSON SBOM")


PARSERS: dict[str, Callable[[bytes, str | None], Iterator[ParsedFinding]]] = {
    "nuclei": parse_nuclei, "trivy": parse_trivy, "grype": parse_grype, "semgrep": parse_semgrep,
    "gitleaks": parse_gitleaks, "checkov": parse_checkov, "zap": parse_zap, "prowler": parse_prowler,
    "sarif": parse_sarif,
    # Handled by dedicated code paths in the import engine:
    "nmap": None, "sbom": None,  # type: ignore[dict-item]
}
