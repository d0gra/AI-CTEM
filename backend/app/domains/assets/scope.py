"""Authorized-scope enforcement for assessments.

No engine contacts a target unless the organization has recorded an explicit authorization
that covers it. Active techniques additionally require `allow_active` on the covering entry,
and private/loopback destinations require both the entry's `allow_private_network` flag and
the deployment-wide CTEM_ALLOW_PRIVATE_TARGETS switch.
"""

import ipaddress
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import OutOfScope, ValidationFailed
from app.db.base import utcnow
from app.models import ScopeTarget


@dataclass(frozen=True)
class ScopeDecision:
    target: str
    scope_id: str
    allow_active: bool
    allow_private: bool


def normalize_scope_value(kind: str, value: str) -> str:
    value = value.strip()
    if kind == "domain":
        value = value.lower().rstrip(".")
        if value.startswith("*."):
            value = value[2:]
        if not value or "/" in value or ":" in value or " " in value or "." not in value:
            raise ValidationFailed("Domain scope must be a fully qualified domain name")
        return value
    if kind == "cidr":
        try:
            return str(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            raise ValidationFailed("CIDR scope must be a valid IPv4 or IPv6 network") from exc
    if kind == "url":
        parts = urlsplit(value)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValidationFailed("URL scope must be an http(s) URL")
        return value.rstrip("/")
    if kind == "path":
        root = get_settings().repo_scan_root
        if not root:
            raise ValidationFailed("Local path analysis is disabled (CTEM_REPO_SCAN_ROOT is not set)")
        resolved = Path(value).resolve()
        if not resolved.is_relative_to(Path(root).resolve()):
            raise ValidationFailed("Path must be inside the configured repository scan root")
        return str(resolved)
    raise ValidationFailed(f"Unknown scope kind {kind!r}")


def _host_of(target: str) -> str:
    if "://" in target:
        return (urlsplit(target).hostname or "").lower()
    return target.lower().rstrip(".")


def _covers(entry: ScopeTarget, target: str) -> bool:
    host = _host_of(target)
    if entry.kind == "domain":
        return host == entry.value or host.endswith("." + entry.value)
    if entry.kind == "cidr":
        try:
            return ipaddress.ip_address(host.strip("[]")) in ipaddress.ip_network(entry.value)
        except ValueError:
            return False
    if entry.kind == "url":
        if "://" not in target:
            return False
        want, got = urlsplit(entry.value), urlsplit(target)
        same_origin = (want.scheme, want.hostname, want.port) == (got.scheme, got.hostname, got.port)
        want_path = want.path.rstrip("/")
        return same_origin and (got.path == want_path or got.path.startswith(want_path + "/") or not want_path)
    if entry.kind == "path":
        try:
            return Path(target).resolve().is_relative_to(Path(entry.value))
        except (OSError, ValueError):
            return False
    return False


def check_scope(db: Session, target: str, *, active: bool) -> ScopeDecision:
    """Return the covering authorization for `target` or raise OutOfScope."""
    entries = db.execute(
        select(ScopeTarget).where(or_(ScopeTarget.expires_at.is_(None), ScopeTarget.expires_at > utcnow()))
    ).scalars()
    covering = [e for e in entries if _covers(e, target)]
    if not covering:
        raise OutOfScope(f"Target {target!r} is not covered by an authorized scope entry")
    if active:
        covering = [e for e in covering if e.allow_active]
        if not covering:
            raise OutOfScope(f"Active testing is not authorized for {target!r}")
    best = max(covering, key=lambda e: (e.allow_private_network, len(e.value)))
    return ScopeDecision(
        target=target, scope_id=str(best.id), allow_active=best.allow_active,
        allow_private=best.allow_private_network and get_settings().allow_private_targets,
    )
