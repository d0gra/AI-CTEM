"""Test harness. Tests run against a real PostgreSQL database (RLS cannot be exercised otherwise).

Each test registers its own organization(s), so tests are isolated by tenant rather than by
truncating tables.
"""

import os
import uuid

TEST_DB = os.environ.get("CTEM_TEST_DATABASE", "127.0.0.1:54329/ctem_test")
os.environ.update({
    "CTEM_ENV": "test",
    "CTEM_DATABASE_URL": os.environ.get("CTEM_TEST_APP_URL", f"postgresql+psycopg://ctem_app:ctem_app_dev@{TEST_DB}"),
    "CTEM_MIGRATION_DATABASE_URL": os.environ.get(
        "CTEM_TEST_OWNER_URL", f"postgresql+psycopg://ctem_owner:ctem_owner_dev@{TEST_DB}"
    ),
    "CTEM_COOKIE_SECURE": "false",
    "CTEM_RATE_LIMIT_AUTH": "100000",
    "CTEM_RATE_LIMIT_API": "100000",
    "CTEM_LOG_LEVEL": "WARNING",
    "CTEM_REDIS_URL": "",
    "CTEM_STORAGE_LOCAL_PATH": "/tmp/ctem-test-storage",
    "CTEM_SMTP_HOST": "",
})

import pytest  # noqa: E402
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402

from app.core.config import get_settings  # noqa: E402
from app.core.logging import configure_logging  # noqa: E402

configure_logging()
PASSWORD = "Correct-Horse-Battery-9"


@pytest.fixture(scope="session", autouse=True)
def _database():
    settings = get_settings()
    owner = create_engine(settings.migration_database_url, isolation_level="AUTOCOMMIT")
    with owner.connect() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    owner.dispose()
    cfg = Config(os.path.join(os.path.dirname(__file__), "..", "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(os.path.dirname(__file__), "..", "migrations"))
    command.upgrade(cfg, "head")
    yield


@pytest.fixture(scope="session")
def app(_database):
    from app.main import create_app

    return create_app()


class ApiClient:
    """Bearer-token API client bound to one user."""

    def __init__(self, app, token: str, email: str, org_id: str, user_id: str):
        self.http = TestClient(app)
        self.token, self.email, self.org_id, self.user_id = token, email, org_id, user_id

    def request(self, method: str, path: str, **kw):
        headers = {"Authorization": f"Bearer {self.token}", **kw.pop("headers", {})}
        return self.http.request(method, f"/api/v1{path}", headers=headers, **kw)

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, **kw):
        return self.request("POST", path, **kw)

    def patch(self, path, **kw):
        return self.request("PATCH", path, **kw)

    def put(self, path, **kw):
        return self.request("PUT", path, **kw)

    def delete(self, path, **kw):
        return self.request("DELETE", path, **kw)

    def ok(self, method: str, path: str, expected: int | tuple = (200, 201, 202, 204), **kw):
        r = self.request(method, path, **kw)
        expected = (expected,) if isinstance(expected, int) else expected
        assert r.status_code in expected, f"{method} {path} -> {r.status_code}: {r.text[:600]}"
        return r.json() if r.content else None


@pytest.fixture
def anon(app):
    return TestClient(app)


def login(app, email: str, password: str = PASSWORD) -> ApiClient:
    http = TestClient(app)
    r = http.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]
    me = http.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}).json()
    return ApiClient(app, token, email, me["organization_id"], me["id"])


@pytest.fixture
def make_org(app):
    def _make(name: str = "Acme") -> ApiClient:
        email = f"admin-{uuid.uuid4().hex[:10]}@example.com"
        r = TestClient(app).post("/api/v1/auth/register", json={
            "organization_name": f"{name} {uuid.uuid4().hex[:6]}", "full_name": "Org Admin", "email": email,
            "password": PASSWORD,
        })
        assert r.status_code == 201, r.text
        return login(app, email)

    return _make


@pytest.fixture
def org(make_org) -> ApiClient:
    return make_org()


@pytest.fixture
def make_user(app):
    def _make(admin: ApiClient, role_key: str) -> ApiClient:
        roles = {r["key"]: r["id"] for r in admin.ok("GET", "/admin/roles")}
        email = f"{role_key}-{uuid.uuid4().hex[:8]}@example.com"
        admin.ok("POST", "/admin/users", json={
            "email": email, "full_name": role_key, "password": PASSWORD, "role_id": roles[role_key],
        })
        return login(app, email)

    return _make


@pytest.fixture
def db_for():
    """Open a tenant session for direct database assertions/fixtures."""
    from app.db.session import tenant_session

    def _open(client: ApiClient):
        return tenant_session(uuid.UUID(client.org_id))

    return _open


@pytest.fixture
def drain():
    """Run queued background jobs in-process through the real worker code path."""
    from app.workers.queue import run_pending

    return run_pending


@pytest.fixture
def allow_private(monkeypatch):
    monkeypatch.setattr(get_settings(), "allow_private_targets", True)


class LocalSite:
    """Loopback HTTP server with mutable routes, used as an authorized assessment target."""

    def __init__(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        site = self
        self.routes: dict[str, tuple[int, dict, bytes]] = {}
        self.requests: list[tuple[str, str, dict, bytes]] = []
        self.handler = None  # optional callable(method, path, headers, body) -> (status, headers, body) | None

        class Handler(BaseHTTPRequestHandler):
            def _serve(self):
                length = int(self.headers.get("content-length") or 0)
                body = self.rfile.read(length) if length else b""
                site.requests.append((self.command, self.path, dict(self.headers), body))
                response = site.handler(self.command, self.path, dict(self.headers), body) if site.handler else None
                status, headers, payload = response or site.routes.get(self.path, (404, {}, b"not found"))
                self.send_response(status)
                for k, v in headers.items():
                    for item in v if isinstance(v, list) else [v]:
                        self.send_header(k, item)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            do_GET = do_POST = _serve

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def site():
    s = LocalSite()
    yield s
    s.close()
