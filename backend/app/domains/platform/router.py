"""Cross-organization administration for platform operators (permission `platform:admin`).

Granted only through `python -m app.cli grant-super-admin <email>`. Operators can see every
organization's size and activity and suspend or reinstate an organization. They cannot read
another organization's assets, findings or evidence through these endpoints.
"""

import uuid

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import func, select

from app.api.deps import Principal, require
from app.core.config import get_settings
from app.core.errors import Forbidden, NotFound
from app.db.session import system_session
from app.domains.audit import service as audit
from app.domains.auth.service import revoke_all_sessions
from app.models import Asset, Finding, Organization, User

router = APIRouter(prefix="/platform", tags=["Platform administration"])


class OrgStatusIn(BaseModel):
    is_active: bool


def _counts(db, model) -> dict:
    return dict(db.execute(select(model.organization_id, func.count()).group_by(model.organization_id)).all())


@router.get("/organizations")
def list_organizations(_: Principal = require("platform:admin")) -> list[dict]:
    with system_session() as db:
        users, assets, findings = _counts(db, User), _counts(db, Asset), _counts(db, Finding)
        last_login = dict(db.execute(select(User.organization_id, func.max(User.last_login_at)).group_by(User.organization_id)).all())
        orgs = db.execute(select(Organization).order_by(Organization.created_at)).scalars().all()
        return [{"id": o.id, "name": o.name, "slug": o.slug, "is_active": o.is_active, "created_at": o.created_at,
                 "users": users.get(o.id, 0), "assets": assets.get(o.id, 0), "findings": findings.get(o.id, 0),
                 "last_sign_in_at": last_login.get(o.id)} for o in orgs]


@router.patch("/organizations/{organization_id}")
def set_organization_status(organization_id: uuid.UUID, body: OrgStatusIn, principal: Principal = require("platform:admin")) -> dict:
    if get_settings().demo_mode and not body.is_active:
        raise Forbidden("Organizations cannot be suspended on the public demo")
    if organization_id == principal.organization_id and not body.is_active:
        raise Forbidden("You cannot suspend your own organization")
    with system_session() as db:
        org = db.get(Organization, organization_id)
        if org is None:
            raise NotFound("Organization not found")
        org.is_active = body.is_active
        if not body.is_active:  # end every session in the suspended organization
            for user_id in db.execute(select(User.id).where(User.organization_id == org.id)).scalars():
                revoke_all_sessions(db, user_id)
        for org_id in {org.id, principal.organization_id}:
            audit.record(db, organization_id=org_id, action="platform.organization_" + ("reinstated" if body.is_active else "suspended"),
                         actor_user_id=principal.user_id, actor_email=principal.email, entity_type="organization", entity_id=org.id)
        return {"id": org.id, "is_active": org.is_active}
