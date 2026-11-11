"""Domain and subdomain discovery using DNS resolution and certificate transparency.

Sources are passive or public: recursive DNS queries and the crt.sh certificate-transparency
index. No traffic is sent to the discovered hosts themselves.
"""

import ipaddress
import secrets
from typing import Any

import dns.exception
import dns.resolver
from pydantic import BaseModel, Field

from app.core.net import BlockedDestination, is_public_ip, safe_fetch
from app.domains.assessments.service import EngineContext, EngineSpec, register
from app.domains.assets.service import AssetSpec
from app.domains.findings.service import EvidenceInput, FindingInput

DEFAULT_LABELS = [
    "www", "api", "app", "admin", "portal", "mail", "vpn", "remote", "dev", "staging", "test", "qa", "uat",
    "beta", "demo", "internal", "git", "ci", "jenkins", "grafana", "status", "docs", "cdn", "static", "auth",
    "login", "sso", "m", "shop", "blog", "support", "ai", "chat", "llm", "ml", "models", "inference", "mcp",
]
# Suffixes of third-party services where an unclaimed CNAME target can typically be registered
# by anyone. A dangling record pointing at one of these is a likely subdomain takeover.
TAKEOVER_SUFFIXES = (
    "s3.amazonaws.com", "s3-website", "cloudfront.net", "github.io", "herokuapp.com", "herokudns.com",
    "azurewebsites.net", "trafficmanager.net", "cloudapp.net", "blob.core.windows.net", "netlify.app",
    "vercel.app", "pages.dev", "ghost.io", "zendesk.com", "readme.io", "surge.sh", "bitbucket.io",
    "fastly.net", "myshopify.com", "unbouncepages.com", "wpengine.com", "webflow.io",
)


class DnsDiscoveryConfig(BaseModel):
    use_certificate_transparency: bool = True
    labels: list[str] = Field(default=DEFAULT_LABELS, max_length=500)
    max_subdomains: int = Field(default=250, ge=1, le=2000)


def query(name: str, rtype: str) -> tuple[str, list[str]]:
    """Resolve one record set. Returns (status, values) with status ok | nxdomain | nodata | error."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    try:
        answer = resolver.resolve(name, rtype, raise_on_no_answer=False)
        values = [r.to_text().strip('"') if rtype == "TXT" else r.to_text().rstrip(".") for r in answer] if answer.rrset else []
        return ("ok" if values else "nodata"), values
    except dns.resolver.NXDOMAIN:
        return "nxdomain", []
    except (dns.exception.DNSException, OSError):
        return "error", []


def ct_names(domain: str) -> list[str]:
    """Hostnames under `domain` from certificate transparency (crt.sh)."""
    result = safe_fetch("GET", f"https://crt.sh/?q=%25.{domain}&output=json", timeout=30, max_bytes=20 * 1024 * 1024)
    if result.status_code != 200:
        raise RuntimeError(f"crt.sh returned HTTP {result.status_code}")
    names: set[str] = set()
    for entry in result.json():
        for name in str(entry.get("name_value", "")).splitlines():
            name = name.strip().lower().lstrip("*.")
            if name.endswith("." + domain) and " " not in name and "@" not in name:
                names.add(name)
    return sorted(names)


def _exposure(ips: list[str]) -> str:
    if not ips:
        return "unknown"
    return "internet" if any(is_public_ip(ipaddress.ip_address(ip)) for ip in ips) else "internal"


def _resolve_host(name: str) -> dict:
    cname_status, cname = query(name, "CNAME")
    _, a = query(name, "A")
    _, aaaa = query(name, "AAAA")
    status = "ok" if (a or aaaa) else cname_status
    if cname and not (a or aaaa):
        target_status, _ = query(cname[0], "A")
        status = "dangling" if target_status == "nxdomain" else "unresolved"
    return {"status": status, "a": a, "aaaa": aaaa, "cname": cname}


def _email_findings(ctx: EngineContext, asset, domain: str, txt: list[str], mx: list[str]) -> None:
    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    _, dmarc_txt = query(f"_dmarc.{domain}", "TXT")
    dmarc = [t for t in dmarc_txt if t.lower().startswith("v=dmarc1")]
    severity = "medium" if mx else "low"
    common: dict[str, Any] = {"asset": asset, "source": ctx.source, "domain": "attack_surface", "confidence": "confirmed", "cwe": "CWE-290"}
    if not spf:
        ctx.finding(FindingInput(
            **common, rule_id="dns.spf.missing", title=f"No SPF record published for {domain}", severity=severity,
            description="The domain publishes no SPF policy, so receiving mail servers cannot verify which hosts may send mail for it.",
            technical_impact="Attackers can send email that appears to originate from this domain.",
            remediation='Publish a TXT record such as "v=spf1 include:<provider> -all" listing authorised senders.',
            evidence=[EvidenceInput("dns", f"TXT records for {domain}", {"name": domain, "type": "TXT", "values": txt})],
        ))
    elif any("+all" in t.lower().split() for t in spf):
        ctx.finding(FindingInput(
            **common, rule_id="dns.spf.permissive", title=f"SPF record for {domain} authorises any sender (+all)",
            severity="high", description="The SPF policy ends in +all, which passes every sending host.",
            remediation="Replace +all with -all (or ~all during rollout) after listing legitimate senders.",
            evidence=[EvidenceInput("dns", f"SPF record for {domain}", {"name": domain, "values": spf})],
        ))
    if not dmarc:
        ctx.finding(FindingInput(
            **common, rule_id="dns.dmarc.missing", title=f"No DMARC policy published for {domain}", severity=severity,
            description="Without DMARC, receivers have no instruction to reject mail that fails SPF/DKIM alignment.",
            technical_impact="Spoofed mail using this domain is more likely to be delivered.",
            remediation='Publish "_dmarc" TXT "v=DMARC1; p=quarantine; rua=mailto:<address>" and move to p=reject.',
            evidence=[EvidenceInput("dns", f"TXT records for _dmarc.{domain}", {"name": f"_dmarc.{domain}", "values": dmarc_txt})],
        ))
    elif any("p=none" in t.lower().replace(" ", "") for t in dmarc):
        ctx.finding(FindingInput(
            **common, rule_id="dns.dmarc.monitor_only", title=f"DMARC policy for {domain} is monitor-only (p=none)",
            severity="low", description="The DMARC policy requests no enforcement for failing mail.",
            remediation="Move the policy to p=quarantine and then p=reject once reports show legitimate mail is aligned.",
            evidence=[EvidenceInput("dns", f"DMARC record for {domain}", {"values": dmarc})],
        ))


def run(ctx: EngineContext) -> None:
    config: DnsDiscoveryConfig = ctx.config  # type: ignore[assignment]
    for index, target in enumerate(ctx.targets):
        domain = target.value.lower().rstrip(".")
        ctx.scope(domain)
        if ctx.dry_run:
            ctx.planned(f"Resolve DNS records for {domain} and up to {config.max_subdomains} candidate subdomains")
            if config.use_certificate_transparency:
                ctx.planned(f"Query certificate transparency (crt.sh) for names under {domain}")
            continue
        ctx.job.progress(int(100 * index / max(1, len(ctx.targets))), f"Enumerating {domain}")
        records = {rtype: query(domain, rtype)[1] for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CAA")}
        ctx.stats["requests"] += 6
        root_ips = records["A"] + records["AAAA"]
        root = ctx.asset(AssetSpec(type="domain", identifier=domain, exposure=_exposure(root_ips),
                                   attributes={"dns": records}))
        _email_findings(ctx, root, domain, records["TXT"], records["MX"])
        if not records["CAA"]:
            ctx.finding(FindingInput(
                asset=root, source=ctx.source, rule_id="dns.caa.missing", domain="attack_surface", severity="info",
                confidence="confirmed", title=f"No CAA record restricts certificate issuance for {domain}",
                description="Any public certificate authority may issue certificates for this domain.",
                remediation="Publish CAA records naming the certificate authorities you use.",
                evidence=[EvidenceInput("dns", f"CAA lookup for {domain}", {"name": domain, "values": []})],
            ))
        for ip in root_ips:
            ip_asset = ctx.asset(AssetSpec(type="ip_address", identifier=ip, exposure=_exposure([ip])))
            ctx.link(root, ip_asset, "RESOLVES_TO", evidence={"record": "A/AAAA", "name": domain})

        candidates = {f"{label}.{domain}" for label in config.labels if label.strip()}
        if config.use_certificate_transparency:
            try:
                found = ct_names(domain)
                candidates.update(found)
                ctx.stats["ct_names"] = ctx.stats.get("ct_names", 0) + len(found)
            except (RuntimeError, BlockedDestination, ValueError, OSError) as exc:
                ctx.skip(f"crt.sh:{domain}", f"Certificate transparency lookup failed: {exc}")
        wildcard = _resolve_host(f"{secrets.token_hex(8)}.{domain}")
        wildcard_ips = set(wildcard["a"] + wildcard["aaaa"])
        if wildcard_ips:
            root.attributes = {**root.attributes, "wildcard_dns": sorted(wildcard_ips)}
        unresolved = 0
        for name in sorted(candidates)[: config.max_subdomains]:
            ctx.checkpoint()
            info = _resolve_host(name)
            ctx.stats["requests"] += 3
            ips = info["a"] + info["aaaa"]
            if info["status"] == "dangling":
                sub = ctx.asset(AssetSpec(type="subdomain", identifier=name, attributes={"dns": info}))
                ctx.link(root, sub, "CONTAINS")
                cname = info["cname"][0]
                takeover = any(suffix in cname for suffix in TAKEOVER_SUFFIXES)
                ctx.finding(FindingInput(
                    asset=sub, source=ctx.source, rule_id="dns.cname.dangling", domain="attack_surface",
                    severity="high" if takeover else "medium", confidence="firm" if takeover else "tentative",
                    title=f"Dangling CNAME: {name} points to non-existent {cname}", cwe="CWE-350",
                    description="The record aliases a hostname that no longer exists."
                    + (" The target belongs to a third-party service where unclaimed names can usually be registered,"
                       " which makes subdomain takeover likely." if takeover else ""),
                    technical_impact="An attacker who registers the target can serve content from this subdomain.",
                    business_impact="Phishing, session theft and brand abuse under a trusted hostname.",
                    remediation="Remove the DNS record, or re-provision the resource it referenced.",
                    reproduction=f"dig +short CNAME {name}; dig +short A {cname}",
                    evidence=[EvidenceInput("dns", f"CNAME chain for {name}", {"name": name, "cname": cname, "target_status": "NXDOMAIN"})],
                ))
                ctx.mark_complete(sub)
                continue
            if not ips or (wildcard_ips and set(ips) <= wildcard_ips and not info["cname"]):
                unresolved += 1
                continue
            sub = ctx.asset(AssetSpec(type="subdomain", identifier=name, exposure=_exposure(ips), attributes={"dns": info}))
            ctx.link(root, sub, "CONTAINS")
            ctx.mark_complete(sub)
            for ip in ips:
                ip_asset = ctx.asset(AssetSpec(type="ip_address", identifier=ip, exposure=_exposure([ip])))
                ctx.link(sub, ip_asset, "RESOLVES_TO", evidence={"record": "A/AAAA", "name": name})
        ctx.stats["candidates_not_resolving"] = ctx.stats.get("candidates_not_resolving", 0) + unresolved
        ctx.mark_complete(root)


register(EngineSpec(
    kind="dns_discovery", permission="discovery:run", name="Domain and subdomain discovery", module="attack_surface", run=run,
    description="Enumerates DNS records and subdomains from DNS and certificate transparency; flags email "
                "spoofing weaknesses and dangling records.",
    config_model=DnsDiscoveryConfig, target_kinds=("domain",), active=False,
))
