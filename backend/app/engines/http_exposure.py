"""HTTP service and TLS exposure assessment.

Sends a small, bounded number of read-only GET requests per target (the landing page, one
CORS probe and a short list of well-known paths). Requires active-testing authorization.
"""

import re
import socket
import ssl
from datetime import UTC, datetime
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from pydantic import BaseModel, Field

from app.core.net import BlockedDestination, FetchResult, is_public_ip, resolve_host, safe_fetch
from app.domains.assessments.service import EngineContext, EngineSpec, register
from app.domains.assets.service import AssetSpec
from app.domains.findings.service import EvidenceInput, FindingInput
from app.models import Asset

CORS_PROBE_ORIGIN = "https://cors-probe.ctem-assessment.example"

# (path, rule suffix, title, severity, validator(body, headers) -> bool, remediation)
SENSITIVE_PATHS: list[tuple[str, str, str, str, object, str]] = [
    ("/.git/HEAD", "git_exposed", "Git repository metadata is publicly readable", "high",
     lambda b, h: b.lstrip().startswith(b"ref: refs/") or re.fullmatch(rb"[0-9a-f]{40}\s*", b) is not None,
     "Block access to /.git at the web server and remove the repository from the web root."),
    ("/.env", "env_file_exposed", "Environment file is publicly readable", "critical",
     lambda b, h: b"<html" not in b[:500].lower() and re.search(rb"(?m)^[A-Z][A-Z0-9_]{2,}=.+", b) is not None,
     "Remove the file from the web root, block dotfiles at the web server and rotate every credential it contains."),
    ("/server-status", "apache_status", "Apache server-status page is publicly accessible", "medium",
     lambda b, h: b"Apache Server Status" in b, "Restrict mod_status to trusted addresses."),
    ("/actuator/env", "spring_actuator_env", "Spring Boot actuator environment endpoint is exposed", "high",
     lambda b, h: b'"propertySources"' in b, "Disable or authenticate actuator endpoints."),
    ("/phpinfo.php", "phpinfo", "phpinfo() output is publicly accessible", "medium",
     lambda b, h: b"phpinfo()" in b and b"PHP Version" in b, "Remove diagnostic scripts from production."),
    ("/debug/pprof/", "go_pprof", "Go pprof debug endpoint is exposed", "medium",
     lambda b, h: b"Types of profiles available" in b, "Do not expose net/http/pprof on public listeners."),
    ("/metrics", "metrics_exposed", "Prometheus metrics endpoint is publicly accessible", "low",
     lambda b, h: b"# HELP " in b[:4000] and b"# TYPE " in b[:8000], "Restrict the metrics endpoint to the monitoring network."),
]
API_DOC_PATHS = ("/openapi.json", "/swagger.json", "/v3/api-docs", "/api/openapi.json")
# Product markers that identify an administrative or data-plane console.
MANAGEMENT_MARKERS: list[tuple[str, re.Pattern, str]] = [
    ("Jenkins", re.compile(rb"<title>[^<]*Jenkins", re.I), "high"),
    ("Grafana", re.compile(rb"<title>Grafana</title>", re.I), "medium"),
    ("Kibana", re.compile(rb"kbn-injected-metadata|<title>Kibana", re.I), "medium"),
    ("phpMyAdmin", re.compile(rb"<title>[^<]*phpMyAdmin", re.I), "high"),
    ("Adminer", re.compile(rb"<title>[^<]*Adminer", re.I), "high"),
    ("Jupyter", re.compile(rb"<title>[^<]*(Jupyter|JupyterLab)", re.I), "high"),
    ("MLflow", re.compile(rb"<title>MLflow</title>", re.I), "high"),
    ("Portainer", re.compile(rb"<title>Portainer</title>", re.I), "high"),
    ("Kubernetes Dashboard", re.compile(rb"<title>Kubernetes Dashboard</title>", re.I), "high"),
    ("Open WebUI", re.compile(rb"<title>Open WebUI</title>", re.I), "medium"),
    ("Gradio", re.compile(rb"gradio-app|window\.gradio_config", re.I), "medium"),
]
COOKIE_TECH = {"phpsessid": "PHP", "jsessionid": "Java", "asp.net_sessionid": "ASP.NET", "laravel_session": "Laravel",
               "connect.sid": "Express", "csrftoken": "Django", "_rails": "Ruby on Rails"}


class HttpExposureConfig(BaseModel):
    check_sensitive_paths: bool = True
    check_cors: bool = True
    check_tls: bool = True
    request_budget_per_target: int = Field(default=20, ge=3, le=60)


def _exchange(result: FetchResult, method: str = "GET", request_headers: dict | None = None) -> EvidenceInput:
    interesting = ("server", "x-powered-by", "strict-transport-security", "content-security-policy", "location",
                   "x-frame-options", "x-content-type-options", "access-control-allow-origin", "content-type",
                   "access-control-allow-credentials", "www-authenticate", "referrer-policy")
    return EvidenceInput("http_exchange", f"{method} {result.url} -> HTTP {result.status_code}", {
        "request": {"method": method, "url": result.url, "headers": request_headers or {}},
        "response": {"status": result.status_code, "headers": {k: v for k, v in result.headers.items() if k in interesting},
                     "body_excerpt": result.text()[:600], "resolved_ip": result.resolved_ip},
    })


def fetch_certificate(host: str, port: int, *, allow_private: bool, timeout: float = 8.0) -> dict:
    """Connect to the validated address and return certificate and protocol details."""
    ip = resolve_host(host, allow_private=allow_private)[0]
    context = ssl.create_default_context()
    context.check_hostname, context.verify_mode = False, ssl.CERT_NONE  # inspect even invalid certificates
    with socket.create_connection((ip, port), timeout=timeout) as raw, context.wrap_socket(raw, server_hostname=host) as tls:
        der = tls.getpeercert(binary_form=True)
        protocol, cipher = tls.version(), tls.cipher()
    trusted, trust_error = True, None
    try:
        verify = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout=timeout) as raw, verify.wrap_socket(raw, server_hostname=host):
            pass
    except ssl.SSLCertVerificationError as exc:
        trusted, trust_error = False, exc.verify_message
    except (OSError, ssl.SSLError) as exc:
        trusted, trust_error = False, str(exc)
    cert = x509.load_der_x509_certificate(der or b"")
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    return {
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(), "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(), "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(), "sans": sans[:100], "protocol": protocol,
        "cipher": cipher[0] if cipher else None, "trusted": trusted, "trust_error": trust_error,
        "self_signed": cert.issuer == cert.subject,
        "days_remaining": (cert.not_valid_after_utc - datetime.now(UTC)).days,
    }


def _tls_findings(ctx: EngineContext, site: Asset, host: str, port: int, allow_private: bool) -> None:
    try:
        info = fetch_certificate(host, port, allow_private=allow_private)
    except (OSError, ssl.SSLError, ValueError, BlockedDestination) as exc:
        ctx.skip(f"tls:{host}:{port}", f"TLS inspection failed: {exc}")
        return
    cert_asset = ctx.asset(AssetSpec(type="certificate", identifier=info["fingerprint_sha256"],
                                     name=f"Certificate {info['subject'] or host}", attributes=info))
    ctx.link(site, cert_asset, "SECURED_BY", evidence={"host": host, "port": port})
    evidence = [EvidenceInput("tls", f"TLS handshake with {host}:{port}", info)]
    common = {"asset": site, "source": ctx.source, "domain": "attack_surface", "confidence": "confirmed", "evidence": evidence}
    days = info["days_remaining"]
    if days < 0:
        ctx.finding(FindingInput(**common, rule_id="tls.cert.expired", severity="high", cwe="CWE-298",
                                 title=f"TLS certificate for {host} expired {-days} day(s) ago",
                                 description="Clients will reject the connection or users will be trained to bypass warnings.",
                                 remediation="Renew and deploy the certificate; automate renewal."))
    elif days <= 30:
        ctx.finding(FindingInput(**common, rule_id="tls.cert.expiring", severity="medium" if days <= 14 else "low",
                                 title=f"TLS certificate for {host} expires in {days} day(s)",
                                 description="The certificate is close to expiry.",
                                 remediation="Renew the certificate and verify automated renewal is working."))
    if not info["trusted"] and days >= 0:
        ctx.finding(FindingInput(**common, rule_id="tls.cert.untrusted", severity="medium", cwe="CWE-295",
                                 title=f"TLS certificate for {host} is not trusted"
                                 + (" (self-signed)" if info["self_signed"] else ""),
                                 description=f"Validation against the public trust store failed: {info['trust_error']}.",
                                 remediation="Deploy a certificate issued by a trusted CA that covers this hostname."))
    if info["protocol"] in ("TLSv1", "TLSv1.1", "SSLv3"):
        ctx.finding(FindingInput(**common, rule_id="tls.protocol.legacy", severity="high", cwe="CWE-326",
                                 title=f"{host} negotiates deprecated protocol {info['protocol']}",
                                 description="TLS 1.0/1.1 are deprecated (RFC 8996) and vulnerable to known attacks.",
                                 remediation="Disable TLS 1.0 and 1.1; require TLS 1.2 or later."))


def _header_findings(ctx: EngineContext, site: Asset, result: FetchResult, is_https: bool) -> None:
    h = result.headers
    ev = [_exchange(result)]
    common = {"asset": site, "source": ctx.source, "domain": "web", "confidence": "confirmed", "evidence": ev}
    if is_https and "strict-transport-security" not in h:
        ctx.finding(FindingInput(**common, rule_id="http.header.hsts_missing", severity="low", cwe="CWE-319",
                                 title="HTTP Strict Transport Security is not enabled",
                                 description="Without HSTS, browsers may be downgraded to plaintext HTTP on first contact.",
                                 remediation="Send Strict-Transport-Security: max-age=31536000; includeSubDomains."))
    csp = h.get("content-security-policy", "")
    if "text/html" in h.get("content-type", ""):
        if not csp:
            ctx.finding(FindingInput(**common, rule_id="http.header.csp_missing", severity="low", cwe="CWE-693",
                                     title="No Content-Security-Policy header",
                                     description="A content security policy limits the impact of cross-site scripting.",
                                     remediation="Define a Content-Security-Policy appropriate to the application."))
        if "x-frame-options" not in h and "frame-ancestors" not in csp:
            ctx.finding(FindingInput(**common, rule_id="http.header.clickjacking", severity="low", cwe="CWE-1021",
                                     title="Page can be framed by other origins (clickjacking)",
                                     description="Neither X-Frame-Options nor CSP frame-ancestors is set.",
                                     remediation="Send Content-Security-Policy: frame-ancestors 'none' (or 'self')."))
    if "x-content-type-options" not in h:
        ctx.finding(FindingInput(**common, rule_id="http.header.nosniff_missing", severity="info", cwe="CWE-693",
                                 title="X-Content-Type-Options: nosniff is not set",
                                 description="Browsers may MIME-sniff responses.", remediation="Send X-Content-Type-Options: nosniff."))
    disclosed = [f"{k}: {h[k]}" for k in ("server", "x-powered-by", "x-aspnet-version") if re.search(r"\d+\.\d+", h.get(k, ""))]
    if disclosed:
        ctx.finding(FindingInput(**common, rule_id="http.header.version_disclosure", severity="info", cwe="CWE-200",
                                 title="Response headers disclose software versions", description="; ".join(disclosed),
                                 remediation="Suppress version information in server banners."))
    for raw in result.raw_set_cookies[:20]:
        name = raw.split("=", 1)[0].strip()
        flags = raw.lower()
        looks_session = any(s in name.lower() for s in ("sess", "sid", "auth", "token", "jwt"))
        missing = [f for f, present in (("Secure", "; secure" in flags or not is_https), ("HttpOnly", "; httponly" in flags),
                                        ("SameSite", "samesite=" in flags)) if not present]
        if missing and looks_session:
            ctx.finding(FindingInput(**common, rule_id="http.cookie.flags", discriminator=name, severity="medium" if "HttpOnly" in missing or "Secure" in missing else "low",
                                     cwe="CWE-614", title=f"Session cookie '{name}' is missing {', '.join(missing)}",
                                     description="Session cookies without these attributes are easier to steal or replay.",
                                     remediation="Set Secure, HttpOnly and SameSite on session cookies."))


def _fingerprint(result: FetchResult) -> list[str]:
    tech: set[str] = set()
    for key in ("server", "x-powered-by", "x-generator"):
        if result.headers.get(key):
            tech.add(result.headers[key][:60])
    generator = re.search(rb'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']{1,60})', result.body[:20000], re.I)
    if generator:
        tech.add(generator.group(1).decode(errors="replace"))
    for raw in result.raw_set_cookies:
        for marker, name in COOKIE_TECH.items():
            if raw.lower().startswith(marker):
                tech.add(name)
    return sorted(tech)


def _exposure_of(ip: str) -> str:
    import ipaddress

    try:
        return "internet" if is_public_ip(ipaddress.ip_address(ip)) else "internal"
    except ValueError:
        return "unknown"


def _assess_origin(ctx: EngineContext, origin: str, allow_private: bool, config: HttpExposureConfig) -> None:
    parts = urlsplit(origin)
    host, is_https = parts.hostname or "", parts.scheme == "https"
    port = parts.port or (443 if is_https else 80)
    budget = config.request_budget_per_target

    def get(path: str, headers: dict | None = None) -> FetchResult | None:
        nonlocal budget
        if budget <= 0:
            return None
        budget -= 1
        ctx.stats["requests"] += 1
        try:
            return safe_fetch("GET", origin + path, allow_private=allow_private, headers=headers, verify_tls=False,
                              max_redirects=0, max_bytes=512 * 1024)
        except BlockedDestination:
            raise
        except Exception as exc:  # network failure on one path must not abort the assessment
            ctx.skip(origin + path, f"{type(exc).__name__}: {exc}"[:200])
            return None

    landing = get("/")
    if landing is None:
        return
    title = re.search(rb"<title[^>]*>([^<]{1,200})", landing.body[:20000], re.I)
    site = ctx.asset(AssetSpec(
        type="website", identifier=origin, exposure=_exposure_of(landing.resolved_ip),
        attributes={"status_code": landing.status_code, "title": title.group(1).decode(errors="replace").strip() if title else None,
                    "technologies": _fingerprint(landing), "server": landing.headers.get("server"),
                    "redirect": landing.headers.get("location")},
    ))
    for parent_type in ("subdomain", "domain"):
        parent = ctx.db.query(Asset).filter(Asset.type == parent_type, Asset.identifier == host.lower()).one_or_none()
        if parent is not None:
            ctx.link(parent, site, "EXPOSES", evidence={"port": port, "scheme": parts.scheme})
            break
    common = {"asset": site, "source": ctx.source, "confidence": "confirmed"}
    if not is_https:
        location = landing.headers.get("location", "")
        if not (landing.status_code in (301, 302, 307, 308) and location.startswith("https://")):
            ctx.finding(FindingInput(**common, rule_id="http.plaintext", domain="web", severity="medium", cwe="CWE-319",
                                     title=f"{host} serves content over unencrypted HTTP",
                                     description="The service responds over HTTP without redirecting to HTTPS.",
                                     remediation="Redirect all HTTP requests to HTTPS and enable HSTS.",
                                     evidence=[_exchange(landing)]))
    _header_findings(ctx, site, landing, is_https)
    if site.environment in ("staging", "development", "test") and site.exposure == "internet":
        ctx.finding(FindingInput(**common, rule_id="exposure.nonprod_public", domain="attack_surface", severity="low",
                                 title=f"Non-production service is reachable from the internet: {host}",
                                 description=f"The hostname indicates a {site.environment} environment, which usually has weaker controls and test data.",
                                 remediation="Restrict non-production services to a VPN or allow-list.", evidence=[_exchange(landing)]))
    if landing.status_code == 200:
        for product, pattern, severity in MANAGEMENT_MARKERS:
            if pattern.search(landing.body[:60000]):
                ai_related = product in ("Jupyter", "MLflow", "Open WebUI", "Gradio")
                ctx.finding(FindingInput(
                    **common, rule_id="exposure.management_interface", discriminator=product, cwe="CWE-284",
                    domain="ai_infra" if ai_related else "attack_surface", severity=severity,
                    owasp_llm="LLM03:2025" if ai_related else None,
                    title=f"{product} interface is exposed at {origin}",
                    description=f"The landing page identifies a {product} console reachable without a network restriction.",
                    technical_impact="Management consoles are high-value targets for credential attacks and known exploits.",
                    remediation="Place the interface behind SSO/VPN and restrict source addresses.", evidence=[_exchange(landing)]))
                site.attributes = {**site.attributes, "management_interface": product}
    if config.check_cors:
        probe_headers = {"Origin": CORS_PROBE_ORIGIN}
        probe = get("/", probe_headers)
        if probe is not None:
            acao, acac = probe.headers.get("access-control-allow-origin", ""), probe.headers.get("access-control-allow-credentials", "")
            if acao == CORS_PROBE_ORIGIN and acac.lower() == "true":
                ctx.finding(FindingInput(
                    **common, rule_id="http.cors.reflected_credentials", domain="web", severity="high", cwe="CWE-942",
                    title="CORS policy reflects arbitrary origins with credentials",
                    description="The server echoes an attacker-controlled Origin and allows credentials.",
                    technical_impact="Any website can read authenticated responses on behalf of a logged-in user.",
                    remediation="Validate Origin against an allow-list; never combine reflected origins with Access-Control-Allow-Credentials.",
                    reproduction=f"curl -s -D- -o /dev/null -H 'Origin: {CORS_PROBE_ORIGIN}' {origin}/",
                    evidence=[_exchange(probe, request_headers=probe_headers)]))
            elif acao == CORS_PROBE_ORIGIN:
                ctx.finding(FindingInput(**common, rule_id="http.cors.reflected", domain="web", severity="low", cwe="CWE-942",
                                         title="CORS policy reflects arbitrary origins",
                                         description="Any origin may read unauthenticated responses.",
                                         remediation="Restrict Access-Control-Allow-Origin to trusted origins.",
                                         evidence=[_exchange(probe, request_headers=probe_headers)]))
    if config.check_sensitive_paths:
        for path, rule, title_, severity, validator, remediation in SENSITIVE_PATHS:
            ctx.checkpoint()
            r = get(path)
            if r is not None and r.status_code == 200 and validator(r.body, r.headers):  # type: ignore[operator]
                ctx.finding(FindingInput(
                    **common, rule_id=f"exposure.{rule}", domain="web", severity=severity, cwe="CWE-538", title=f"{title_} ({origin}{path})",
                    description="The response content matches the signature of the sensitive resource, not a generic error page.",
                    technical_impact="Discloses source code, credentials or internal state to unauthenticated users.",
                    remediation=remediation, reproduction=f"curl -s {origin}{path} | head", evidence=[_exchange(r)]))
        for path in API_DOC_PATHS:
            r = get(path)
            if r is not None and r.status_code == 200 and re.search(rb'"(openapi|swagger)"\s*:', r.body[:2000]):
                api = ctx.asset(AssetSpec(type="api", identifier=origin + path, name=f"API at {origin}",
                                          exposure=site.exposure, attributes={"spec_url": origin + path}))
                ctx.link(site, api, "EXPOSES")
                ctx.finding(FindingInput(**common, rule_id="exposure.api_docs", domain="api", severity="info",
                                         title=f"API specification is publicly accessible ({origin}{path})",
                                         description="A machine-readable API description is served without authentication.",
                                         remediation="Confirm the specification is intended to be public; run the OpenAPI analysis on it.",
                                         evidence=[_exchange(r)]))
                break
    if is_https and config.check_tls:
        _tls_findings(ctx, site, host, port, allow_private)
    ctx.mark_complete(site)


def run(ctx: EngineContext) -> None:
    config: HttpExposureConfig = ctx.config  # type: ignore[assignment]
    for index, target in enumerate(ctx.targets):
        value = target.value.strip()
        origins = [value.rstrip("/")] if "://" in value else [f"https://{value}", f"http://{value}"]
        for origin in origins:
            parts = urlsplit(origin)
            origin = f"{parts.scheme}://{parts.netloc}"
            decision = ctx.scope(origin, active=True)
            if ctx.dry_run:
                ctx.planned(f"GET {origin}/ plus up to {config.request_budget_per_target - 1} read-only probes; TLS handshake inspection")
                continue
            ctx.job.progress(int(100 * index / max(1, len(ctx.targets))), f"Assessing {origin}")
            _assess_origin(ctx, origin, decision.allow_private, config)


register(EngineSpec(
    kind="http_exposure", name="HTTP and TLS exposure assessment", module="attack_surface", run=run,
    description="Analyses security headers, cookies, CORS, TLS certificates and protocols, exposed management "
                "interfaces and well-known sensitive files using a bounded set of read-only requests.",
    config_model=HttpExposureConfig, target_kinds=("url", "domain"), active=True,
))
