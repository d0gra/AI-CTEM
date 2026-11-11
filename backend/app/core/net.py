"""Outbound network access with SSRF protection.

All server-initiated HTTP requests go through `safe_fetch`. The hostname is resolved once,
every resolved address is checked against the deny rules, and the connection is pinned to the
validated address so a second DNS lookup cannot redirect the request (DNS rebinding).
"""

import contextlib
import ipaddress
import socket
import time
from dataclasses import dataclass, field

import httpx

from app.core.config import get_settings
from app.core.errors import AppError


class BlockedDestination(AppError):
    status_code = 400
    code = "blocked_destination"


_ALWAYS_BLOCKED = [
    ipaddress.ip_network("169.254.0.0/16"),  # link-local incl. cloud metadata
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("ff00::/8"),
    ipaddress.ip_network("100.100.100.200/32"),  # Alibaba metadata
    ipaddress.ip_network("fd00:ec2::254/128"),  # AWS IMDS over IPv6
]


def is_public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def check_ip(ip_text: str, *, allow_private: bool) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    ip = ipaddress.ip_address(ip_text)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if any(ip in net for net in _ALWAYS_BLOCKED) or ip.is_unspecified:
        raise BlockedDestination(f"Destination address {ip} is never permitted")
    if not allow_private and not is_public_ip(ip):
        raise BlockedDestination(f"Destination address {ip} is not publicly routable")
    return ip


def resolve_host(host: str, *, allow_private: bool) -> list[str]:
    """Resolve and validate a hostname. Every returned address has passed the deny rules."""
    try:
        ipaddress.ip_address(host.strip("[]"))
        candidates = [host.strip("[]")]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise BlockedDestination(f"Hostname {host} does not resolve") from exc
        candidates = list(dict.fromkeys(str(i[4][0]) for i in infos))
    if not candidates:
        raise BlockedDestination(f"Hostname {host} does not resolve")
    return [str(check_ip(c, allow_private=allow_private)) for c in candidates]


@dataclass
class FetchResult:
    url: str
    status_code: int
    headers: dict[str, str]
    body: bytes
    truncated: bool = False
    redirect_chain: list[str] = field(default_factory=list)
    resolved_ip: str = ""
    elapsed_ms: int = 0
    raw_set_cookies: list[str] = field(default_factory=list)

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self):
        import json

        return json.loads(self.body)


def safe_fetch(
    method: str,
    url: str,
    *,
    allow_private: bool = False,
    headers: dict[str, str] | None = None,
    content: bytes | None = None,
    json_body: object | None = None,
    timeout: float | None = None,
    max_bytes: int = 2 * 1024 * 1024,
    max_redirects: int = 3,
    verify_tls: bool = True,
    transport: httpx.BaseTransport | None = None,
) -> FetchResult:
    """Perform an HTTP request to a validated destination.

    `transport` is for tests only: when supplied, address validation still runs for IP literals
    but hostname resolution is skipped.
    """
    settings = get_settings()
    timeout = timeout or settings.outbound_timeout_seconds
    chain: list[str] = []
    current = url
    for _ in range(max_redirects + 1):
        parsed = httpx.URL(current)
        if parsed.scheme not in ("http", "https"):
            raise BlockedDestination(f"URL scheme {parsed.scheme!r} is not permitted")
        if parsed.userinfo:
            raise BlockedDestination("URLs with embedded credentials are not permitted")
        host = parsed.host
        if not host:
            raise BlockedDestination("URL has no host")
        request_headers = {"User-Agent": settings.outbound_user_agent, **(headers or {})}
        extensions: dict = {}
        if transport is None:
            ip = resolve_host(host, allow_private=allow_private)[0]
            target = parsed.copy_with(host=ip)
            default_port = 443 if parsed.scheme == "https" else 80
            request_headers["Host"] = host if parsed.port in (None, default_port) else f"{host}:{parsed.port}"
            extensions["sni_hostname"] = host
        else:
            with contextlib.suppress(ValueError):  # a hostname (not an IP literal) with an injected transport
                check_ip(host.strip("[]"), allow_private=allow_private)
            ip, target = "", parsed
        with httpx.Client(verify=verify_tls, timeout=timeout, follow_redirects=False, transport=transport) as client:
            request = client.build_request(
                method, target, headers=request_headers, content=content, json=json_body, extensions=extensions
            )
            started = time.monotonic()
            response = client.send(request, stream=True)
            try:
                body = bytearray()
                truncated = False
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > max_bytes:
                        truncated = True
                        del body[max_bytes:]
                        break
            finally:
                response.close()
        if response.status_code in (301, 302, 303, 307, 308) and "location" in response.headers and max_redirects:
            chain.append(current)
            current = str(parsed.join(response.headers["location"]))
            if response.status_code == 303:
                method, content, json_body = "GET", None, None
            continue
        return FetchResult(
            url=current,
            status_code=response.status_code,
            headers={k.lower(): v for k, v in response.headers.items()},
            body=bytes(body),
            truncated=truncated,
            redirect_chain=chain,
            resolved_ip=ip,
            elapsed_ms=int((time.monotonic() - started) * 1000),
            raw_set_cookies=response.headers.get_list("set-cookie"),
        )
    raise BlockedDestination("Too many redirects")
