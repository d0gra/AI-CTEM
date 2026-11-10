from sqlalchemy import text

from app.domains.audit import service as audit


def test_read_only_user_cannot_administer(org, make_user):
    viewer = make_user(org, "read_only")
    assert viewer.get("/admin/users").status_code == 403
    assert viewer.post("/admin/teams", json={"name": "x"}).status_code == 403
    assert viewer.get("/admin/roles").status_code == 200


def test_cannot_grant_permissions_you_do_not_hold(org, make_user):
    # A custom role with admin:users but without risk:approve must not be able to mint it.
    limited = org.ok("POST", "/admin/roles", json={
        "key": "user_manager", "name": "User manager", "permissions": ["admin:users", "assets:read"],
    })
    manager = make_user(org, "user_manager")
    r = manager.post("/admin/roles", json={"key": "escalate", "name": "Escalate", "permissions": ["risk:approve"]})
    assert r.status_code == 403
    roles = {x["key"]: x["id"] for x in manager.ok("GET", "/admin/roles")}
    r = manager.post("/admin/users", json={
        "email": "esc@example.com", "full_name": "esc", "password": "Correct-Horse-Battery-9",
        "role_id": roles["org_admin"],
    })
    assert r.status_code == 403
    # ... nor modify a more privileged account
    assert manager.patch(f"/admin/users/{org.user_id}", json={"is_active": False}).status_code == 403
    assert limited["permissions"] == ["admin:users", "assets:read"]


def test_cannot_change_own_role_or_modify_builtin(org):
    roles = {r["key"]: r["id"] for r in org.ok("GET", "/admin/roles")}
    assert org.patch(f"/admin/users/{org.user_id}", json={"role_id": roles["read_only"]}).status_code == 403
    assert org.patch(f"/admin/roles/{roles['auditor']}", json={"permissions": []}).status_code == 403
    assert org.post("/admin/roles", json={"key": "bad", "name": "bad", "permissions": ["nope:nope"]}).status_code == 422
    assert org.post("/admin/roles", json={"key": "plat", "name": "plat", "permissions": ["platform:admin"]}).status_code == 403


def test_deactivated_user_loses_access(org, make_user):
    analyst = make_user(org, "security_analyst")
    assert analyst.get("/auth/me").status_code == 200
    org.ok("PATCH", f"/admin/users/{analyst.user_id}", json={"is_active": False})
    assert analyst.get("/auth/me").status_code == 401


def test_teams_crud(org, make_user):
    analyst = make_user(org, "security_analyst")
    team = org.ok("POST", "/admin/teams", json={"name": "AppSec", "member_ids": [analyst.user_id]})
    assert team["member_ids"] == [analyst.user_id]
    assert org.post("/admin/teams", json={"name": "AppSec"}).status_code == 409
    org.ok("PUT", f"/admin/teams/{team['id']}", json={"name": "AppSec", "member_ids": []})
    org.ok("DELETE", f"/admin/teams/{team['id']}", expected=204)


def test_audit_chain_is_valid_and_append_only(org, db_for):
    org.ok("POST", "/admin/teams", json={"name": "Audited"})
    with db_for(org) as db:
        result = audit.verify_chain(db, org.org_id)
        assert result["valid"] and result["events"] >= 3
    # The application role cannot rewrite history.
    import pytest
    from sqlalchemy.exc import ProgrammingError

    with pytest.raises(ProgrammingError), db_for(org) as db:
        db.execute(text("UPDATE audit_events SET action = 'tampered'"))
    with pytest.raises(ProgrammingError), db_for(org) as db:
        db.execute(text("DELETE FROM audit_events"))
