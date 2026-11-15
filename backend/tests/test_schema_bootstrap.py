"""A fresh installation: the schema-version check, the errors an unmigrated database produces, and
creating the first organization from the CLI when self-service registration is off."""

import re
import uuid

import pytest
from sqlalchemy import text

from app.db import schema
from app.db.session import get_engine
from tests.conftest import PASSWORD, login


def _behind(monkeypatch):
    """Pretend this build expects a migration the test database has not had."""
    known = schema._revisions()[1]
    monkeypatch.setattr(schema, "_revisions", lambda: (frozenset({"9999"}), known | {"9999"}))


def test_schema_state_at_head():
    with get_engine().connect() as conn:
        status, _ = schema.state(conn)
    assert status == "ok"
    assert schema.main(["status"]) == 0


def test_schema_state_behind_and_newer(monkeypatch):
    heads, known = schema._revisions()
    # This build expects a revision the database does not have yet: behind, not ready.
    monkeypatch.setattr(schema, "_revisions", lambda: (frozenset({"9999"}), known | {"9999"}))
    with get_engine().connect() as conn:
        status, detail = schema.state(conn)
    assert status == "behind" and "9999" in detail
    # The database is at a revision this build has never heard of: a later release migrated it.
    monkeypatch.setattr(schema, "_revisions", lambda: (frozenset({"0001"}), frozenset({"0001"})))
    with get_engine().connect() as conn:
        assert schema.state(conn)[0] == "newer"


def test_schema_state_missing():
    class Empty:
        def execute(self, *_a, **_k):
            class Result:
                def scalar(self):
                    return None
            return Result()

    assert schema.state(Empty())[0] == "missing"


def test_wait_gives_up_with_instructions(monkeypatch, capsys):
    _behind(monkeypatch)
    assert schema.wait(timeout=0) == 1
    err = capsys.readouterr().err
    assert "migrate role" in err and "9999" in err


def test_readiness_requires_the_schema(anon, monkeypatch):
    ready = anon.get("/readyz")
    assert ready.status_code == 200 and ready.json()["checks"]["schema"] == "ok"
    _behind(monkeypatch)
    ready = anon.get("/readyz")
    assert ready.status_code == 503
    assert ready.json()["checks"]["schema"].startswith("behind")


def test_missing_table_is_reported_as_schema_not_ready(anon, monkeypatch):
    from app.domains.auth import service

    def unmigrated(db, **_kw):
        db.execute(text("select * from table_from_a_migration_not_yet_applied"))

    monkeypatch.setattr(service, "create_organization", unmigrated)
    r = anon.post("/api/v1/auth/register", json={
        "organization_name": "Unmigrated", "full_name": "Admin", "email": f"u-{uuid.uuid4().hex[:8]}@example.com",
        "password": PASSWORD,
    })
    assert r.status_code == 503
    body = r.json()["error"]
    assert body["code"] == "schema_not_ready" and "migrat" in body["message"]
    assert "table_from_a_migration" not in r.text  # no SQL reaches the client


def test_cli_creates_the_first_organization(app, anon, monkeypatch, capsys):
    from app import cli
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "allow_registration", False)
    email = f"first-{uuid.uuid4().hex[:8]}@example.com"
    cli.create_organization_cmd("First Corp", email, "First Admin")
    out = capsys.readouterr().out
    assert "First Corp" in out and email in out
    token = re.search(r"reset-password\?token=([\w-]+)&invite=1", out).group(1)

    # No password works until the link is used.
    assert anon.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD}).status_code == 401
    assert anon.post("/api/v1/auth/password/reset", json={"token": token, "new_password": PASSWORD}).status_code == 204
    admin = login(app, email)
    me = admin.ok("GET", "/auth/me")
    assert me["full_name"] == "First Admin" and me["email_verified"] is True
    assert "org_admin" in {r["key"] for r in admin.ok("GET", "/admin/roles")}
    assert admin.ok("GET", "/policies")  # default policies were installed, as for self-registration

    with pytest.raises(SystemExit, match="already exists"):
        cli.create_organization_cmd("Second Corp", email, None)
