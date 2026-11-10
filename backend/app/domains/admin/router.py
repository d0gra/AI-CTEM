"""Administration: users, roles, teams, organization settings."""

import uuid
from datetime import datetime

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy import func, select

from app.api.deps import CurrentUser, Db, Page, Paging, Principal, audit_event, paginate, require
from app.core.errors import Conflict, Forbidden, NotFound, ValidationFailed
from app.core.permissions import PERMISSIONS
from app.core.security import hash_password
from app.domains.auth.service import issue_email_verification, revoke_all_sessions, validate_password
from app.models import Organization, Role, RolePermission, Team, TeamMember, User

router = APIRouter(prefix="/admin", tags=["Administration"])


class RoleOut(BaseModel):
    id: uuid.UUID
    key: str
    name: str
    is_builtin: bool
    permissions: list[str]


class RoleIn(BaseModel):
    key: str = Field(pattern=r"^[a-z][a-z0-9_]{2,62}$")
    name: str = Field(min_length=2, max_length=120)
    permissions: list[str]


class RolePatch(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=120)
    permissions: list[str] | None = None


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    email: str
    full_name: str
    role_id: uuid.UUID
    role_key: str
    is_active: bool
    mfa_enabled: bool
    email_verified_at: datetime | None
    last_login_at: datetime | None
    created_at: datetime


class UserIn(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=1, max_length=200)
    password: str = Field(min_length=12, max_length=256)
    role_id: uuid.UUID


class UserPatch(BaseModel):
    full_name: str | None = Field(default=None, min_length=1, max_length=200)
    role_id: uuid.UUID | None = None
    is_active: bool | None = None


class TeamOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    business_unit: str | None
    member_ids: list[uuid.UUID]


class TeamIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = ""
    business_unit: str | None = Field(default=None, max_length=120)
    member_ids: list[uuid.UUID] = []


def _role_out(r: Role) -> RoleOut:
    return RoleOut(id=r.id, key=r.key, name=r.name, is_builtin=r.is_builtin, permissions=sorted(r.permission_keys))


def _user_out(u: User) -> UserOut:
    return UserOut(
        id=u.id, email=u.email, full_name=u.full_name, role_id=u.role_id, role_key=u.role.key,
        is_active=u.is_active, mfa_enabled=u.mfa_enabled, email_verified_at=u.email_verified_at,
        last_login_at=u.last_login_at, created_at=u.created_at,
    )


def _check_grantable(principal: Principal, permissions: set[str]) -> None:
    """Privilege-escalation guard: nobody can grant permissions they do not hold themselves."""
    unknown = permissions - set(PERMISSIONS)
    if unknown:
        raise ValidationFailed(f"Unknown permissions: {sorted(unknown)}")
    excess = permissions - principal.permissions
    if excess:
        raise Forbidden("You cannot grant permissions you do not hold", details={"permissions": sorted(excess)})


@router.get("/permissions")
def list_permissions(_: Principal = require("admin:users")) -> dict[str, str]:
    return {k: v for k, v in PERMISSIONS.items() if k != "platform:admin"}


@router.get("/roles", response_model=list[RoleOut])
def list_roles(db: Db, _: CurrentUser) -> list[RoleOut]:
    return [_role_out(r) for r in db.execute(select(Role).order_by(Role.name)).scalars().unique()]


@router.post("/roles", response_model=RoleOut, status_code=201)
def create_role(body: RoleIn, db: Db, principal: Principal = require("admin:users")) -> RoleOut:
    _check_grantable(principal, set(body.permissions))
    if db.execute(select(Role.id).where(Role.key == body.key)).first():
        raise Conflict("A role with this key already exists")
    role = Role(organization_id=principal.organization_id, key=body.key, name=body.name)
    role.permissions = [
        RolePermission(organization_id=principal.organization_id, permission_key=p) for p in set(body.permissions)
    ]
    db.add(role)
    db.flush()
    audit_event(db, principal, "role.created", entity_type="role", entity_id=role.id,
                data={"permissions": sorted(body.permissions)})
    return _role_out(role)


@router.patch("/roles/{role_id}", response_model=RoleOut)
def update_role(role_id: uuid.UUID, body: RolePatch, db: Db, principal: Principal = require("admin:users")) -> RoleOut:
    role = db.get(Role, role_id)
    if role is None:
        raise NotFound("Role not found")
    if role.is_builtin:
        raise Forbidden("Built-in roles cannot be modified; create a custom role instead")
    if body.name:
        role.name = body.name
    if body.permissions is not None:
        _check_grantable(principal, set(body.permissions))
        role.permissions = [
            RolePermission(organization_id=principal.organization_id, permission_key=p)
            for p in set(body.permissions)
        ]
    db.flush()
    audit_event(db, principal, "role.updated", entity_type="role", entity_id=role.id,
                data=body.model_dump(exclude_none=True))
    return _role_out(role)


@router.delete("/roles/{role_id}", status_code=204)
def delete_role(role_id: uuid.UUID, db: Db, principal: Principal = require("admin:users")) -> None:
    role = db.get(Role, role_id)
    if role is None:
        raise NotFound("Role not found")
    if role.is_builtin:
        raise Forbidden("Built-in roles cannot be deleted")
    if db.execute(select(func.count()).select_from(User).where(User.role_id == role_id)).scalar_one():
        raise Conflict("Role is still assigned to users")
    db.delete(role)
    audit_event(db, principal, "role.deleted", entity_type="role", entity_id=role_id)


@router.get("/users", response_model=Page[UserOut])
def list_users(db: Db, paging: Paging, _: Principal = require("admin:users")) -> Page[UserOut]:
    rows, total = paginate(db, select(User).order_by(User.email), paging)
    return Page(items=[_user_out(u) for u in rows], total=total, page=paging.page, page_size=paging.page_size)


@router.get("/directory")
def directory(db: Db, _: CurrentUser) -> dict:
    """Minimal user and team listing for assignment pickers (no administrative detail)."""
    users = db.execute(select(User.id, User.full_name, User.email).where(User.is_active).order_by(User.full_name))
    teams = db.execute(select(Team.id, Team.name).order_by(Team.name))
    return {
        "users": [{"id": u.id, "full_name": u.full_name, "email": u.email} for u in users],
        "teams": [{"id": t.id, "name": t.name} for t in teams],
    }


@router.post("/users", response_model=UserOut, status_code=201)
def create_user(body: UserIn, db: Db, principal: Principal = require("admin:users")) -> UserOut:
    role = db.get(Role, body.role_id)
    if role is None:
        raise NotFound("Role not found")
    _check_grantable(principal, role.permission_keys)
    email = body.email.lower()
    validate_password(body.password, email)
    from app.db.session import system_session

    with system_session() as sysdb:  # email uniqueness is global across organizations
        if sysdb.execute(select(User.id).where(User.email == email)).first():
            raise Conflict("A user with this email already exists")
    user = User(organization_id=principal.organization_id, email=email, full_name=body.full_name,
                password_hash=hash_password(body.password), role_id=role.id)
    db.add(user)
    db.flush()
    issue_email_verification(db, user)
    audit_event(db, principal, "user.created", entity_type="user", entity_id=user.id, data={"role": role.key})
    db.refresh(user)
    return _user_out(user)


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(user_id: uuid.UUID, body: UserPatch, db: Db, principal: Principal = require("admin:users")) -> UserOut:
    user = db.get(User, user_id)
    if user is None:
        raise NotFound("User not found")
    if user.id == principal.user_id and (body.role_id is not None or body.is_active is False):
        raise Forbidden("You cannot change your own role or deactivate your own account")
    _check_grantable(principal, user.role.permission_keys)  # cannot manage more privileged accounts
    if body.full_name:
        user.full_name = body.full_name
    if body.role_id is not None and body.role_id != user.role_id:
        role = db.get(Role, body.role_id)
        if role is None:
            raise NotFound("Role not found")
        _check_grantable(principal, role.permission_keys)
        user.role_id = role.id
        revoke_all_sessions(db, user.id)
    if body.is_active is not None:
        user.is_active = body.is_active
        if not body.is_active:
            revoke_all_sessions(db, user.id)
    db.flush()
    audit_event(db, principal, "user.updated", entity_type="user", entity_id=user.id,
                data=body.model_dump(exclude_none=True, mode="json"))
    db.refresh(user)
    return _user_out(user)


def _team_out(t: Team) -> TeamOut:
    return TeamOut(id=t.id, name=t.name, description=t.description, business_unit=t.business_unit,
                   member_ids=[m.user_id for m in t.members])


@router.get("/teams", response_model=list[TeamOut])
def list_teams(db: Db, _: CurrentUser) -> list[TeamOut]:
    return [_team_out(t) for t in db.execute(select(Team).order_by(Team.name)).scalars().unique()]


def _apply_team(db: Db, team: Team, body: TeamIn, org_id: uuid.UUID) -> None:
    team.name, team.description, team.business_unit = body.name, body.description, body.business_unit
    valid = set(db.execute(select(User.id).where(User.id.in_(body.member_ids))).scalars()) if body.member_ids else set()
    if valid != set(body.member_ids):
        raise ValidationFailed("One or more members do not exist")
    team.members = [TeamMember(organization_id=org_id, user_id=u) for u in valid]


@router.post("/teams", response_model=TeamOut, status_code=201)
def create_team(body: TeamIn, db: Db, principal: Principal = require("admin:users")) -> TeamOut:
    if db.execute(select(Team.id).where(Team.name == body.name)).first():
        raise Conflict("A team with this name already exists")
    team = Team(organization_id=principal.organization_id, name=body.name)
    _apply_team(db, team, body, principal.organization_id)
    db.add(team)
    db.flush()
    audit_event(db, principal, "team.created", entity_type="team", entity_id=team.id)
    return _team_out(team)


@router.put("/teams/{team_id}", response_model=TeamOut)
def update_team(team_id: uuid.UUID, body: TeamIn, db: Db, principal: Principal = require("admin:users")) -> TeamOut:
    team = db.get(Team, team_id)
    if team is None:
        raise NotFound("Team not found")
    _apply_team(db, team, body, principal.organization_id)
    db.flush()
    audit_event(db, principal, "team.updated", entity_type="team", entity_id=team.id)
    return _team_out(team)


@router.delete("/teams/{team_id}", status_code=204)
def delete_team(team_id: uuid.UUID, db: Db, principal: Principal = require("admin:users")) -> None:
    team = db.get(Team, team_id)
    if team is None:
        raise NotFound("Team not found")
    db.delete(team)
    audit_event(db, principal, "team.deleted", entity_type="team", entity_id=team_id)


@router.get("/organization")
def get_organization(db: Db, principal: CurrentUser) -> dict:
    org = db.get(Organization, principal.organization_id)
    assert org is not None
    return {"id": org.id, "name": org.name, "slug": org.slug, "created_at": org.created_at}


class OrgPatch(BaseModel):
    name: str = Field(min_length=2, max_length=200)


@router.patch("/organization")
def update_organization(body: OrgPatch, db: Db, principal: Principal = require("admin:org")) -> dict:
    org = db.get(Organization, principal.organization_id)
    assert org is not None
    org.name = body.name
    audit_event(db, principal, "organization.updated", entity_type="organization", entity_id=org.id,
                data={"name": body.name})
    return {"id": org.id, "name": org.name, "slug": org.slug}
