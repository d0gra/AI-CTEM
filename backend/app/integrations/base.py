"""Connector framework.

A connector describes one external system: its configuration and credential schemas, a
connection test, and an honest implementation status:

  available     implemented and exercised by automated tests (fixtures or local execution)
  import_only   results produced by the tool are ingested from files; the platform does not
                call the system directly
  reference     no credentials needed; a public data source synchronised by workers

`live_validated` is false for connectors whose tests use controlled fixtures only because no
real account or binary was available when the connector was built.
"""

import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

import httpx
from pydantic import BaseModel

from app.core.net import BlockedDestination, FetchResult, safe_fetch


class NoSettings(BaseModel):
    pass


@dataclass
class ConnectionResult:
    ok: bool
    detail: str
    error_class: str | None = None  # auth | permission | network | rate_limit | config | upstream | unknown
    metadata: dict = field(default_factory=dict)


@dataclass
class ConnectorSpec:
    key: str
    name: str
    category: str  # scanner | cloud | repository | ai | threat_intel | ticketing | notification
    description: str
    status: str = "available"
    live_validated: bool = False
    config_model: type[BaseModel] = NoSettings
    credentials_model: type[BaseModel] = NoSettings
    test: Callable[..., ConnectionResult] | None = None
    required_permissions: str = ""
    configurable: bool = True  # False for file-import and reference sources


CONNECTORS: dict[str, ConnectorSpec] = {}


def register_connector(spec: ConnectorSpec) -> ConnectorSpec:
    CONNECTORS[spec.key] = spec
    return spec


class ApiError(Exception):
    def __init__(self, message: str, error_class: str, status_code: int | None = None):
        super().__init__(message)
        self.error_class, self.status_code = error_class, status_code


def classify_status(status: int) -> str:
    if status == 401:
        return "auth"
    if status == 403:
        return "permission"
    if status == 429:
        return "rate_limit"
    if status in (400, 404, 422):
        return "config"
    return "upstream" if status >= 500 else "unknown"


class HttpApi:
    """Small JSON API client with SSRF protection, bounded retries and backoff.

    Retries 429 and 5xx responses and network errors, honouring Retry-After. Pagination is
    provided by `paginate`, which follows RFC 8288 `Link: rel="next"` headers.
    """

    def __init__(self, base_url: str, headers: dict[str, str] | None = None, *, allow_private: bool = False,
                 max_retries: int = 3, min_interval: float = 0.0, transport: httpx.BaseTransport | None = None,
                 timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.headers = headers or {}
        self.allow_private, self.max_retries, self.min_interval = allow_private, max_retries, min_interval
        self.transport, self.timeout = transport, timeout
        self._last_request = 0.0
        self.requests_made = 0

    def request(self, method: str, path: str, *, json_body: object | None = None, headers: dict | None = None,
                max_bytes: int = 8 * 1024 * 1024) -> FetchResult:
        url = path if path.startswith("http") else f"{self.base_url}{path}"
        last_error: ApiError | None = None
        for attempt in range(self.max_retries + 1):
            wait = self.min_interval - (time.monotonic() - self._last_request)
            if wait > 0:
                time.sleep(wait)
            self._last_request = time.monotonic()
            self.requests_made += 1
            try:
                result = safe_fetch(method, url, allow_private=self.allow_private, json_body=json_body,
                                    headers={"Accept": "application/json", **self.headers, **(headers or {})},
                                    transport=self.transport, timeout=self.timeout, max_bytes=max_bytes, max_redirects=0)
            except BlockedDestination:
                raise
            except (httpx.HTTPError, OSError) as exc:
                last_error = ApiError(f"Network error: {type(exc).__name__}: {exc}", "network")
            else:
                if result.status_code < 400:
                    return result
                last_error = ApiError(f"HTTP {result.status_code}: {result.text()[:300]}",
                                      classify_status(result.status_code), result.status_code)
                if result.status_code != 429 and result.status_code < 500:
                    raise last_error
                retry_after = result.headers.get("retry-after", "")
                if retry_after.isdigit() and attempt < self.max_retries:
                    time.sleep(min(30, int(retry_after)))
                    continue
            if attempt < self.max_retries:
                time.sleep(min(20, 0.5 * 2 ** attempt))
        assert last_error is not None
        raise last_error

    def get_json(self, path: str, **kw):
        return self.request("GET", path, **kw).json()

    def paginate(self, path: str, *, max_pages: int = 50) -> Iterator[list]:
        url: str | None = path
        for _ in range(max_pages):
            if not url:
                return
            result = self.request("GET", url)
            yield result.json()
            url = None
            for part in result.headers.get("link", "").split(","):
                if 'rel="next"' in part:
                    url = part[part.find("<") + 1: part.find(">")]


def run_test(fn: Callable[[], ConnectionResult]) -> ConnectionResult:
    try:
        return fn()
    except ApiError as exc:
        return ConnectionResult(False, str(exc), exc.error_class)
    except BlockedDestination as exc:
        return ConnectionResult(False, exc.message, "config")
    except Exception as exc:  # connection tests report rather than raise
        return ConnectionResult(False, f"{type(exc).__name__}: {exc}"[:500], "unknown")
