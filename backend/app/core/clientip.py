"""Client address resolution behind reverse proxies.

The direct peer is trusted to report the client address only when it is in CTEM_TRUSTED_PROXIES.
X-Forwarded-For is read from the right, skipping trusted hops, so a client cannot spoof its
address by sending its own X-Forwarded-For header.
"""

import ipaddress
from functools import lru_cache

from starlette.requests import Request

from app.core.config import get_settings


@lru_cache
def _trusted(spec: str) -> tuple:
    return tuple(ipaddress.ip_network(part.strip(), strict=False) for part in spec.split(",") if part.strip())


def _is_trusted(address: str, networks: tuple) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in net for net in networks)


def client_ip(request: Request) -> str | None:
    peer = request.client.host if request.client else None
    networks = _trusted(get_settings().trusted_proxies)
    if peer is None or not _is_trusted(peer, networks):
        return peer
    hops = [h.strip() for h in request.headers.get("x-forwarded-for", "").split(",") if h.strip()]
    for hop in reversed(hops):
        if not _is_trusted(hop, networks):
            try:
                return str(ipaddress.ip_address(hop))
            except ValueError:
                return peer
    return peer
