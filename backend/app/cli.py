"""Operational commands.

    python -m app.cli grant-super-admin <email>   promote an existing user to the platform super administrator role
    python -m app.cli verify-audit <org-slug>     recompute an organization's audit hash chain
    python -m app.cli rotate-secrets              re-encrypt stored secrets with the first key in CTEM_ENCRYPTION_KEYS
    python -m app.cli run-pending                 execute queued jobs once in this process (no scheduler)
"""

import sys

from sqlalchemy import select

import app.api.router  # noqa: F401  (registers engines and job handlers)
from app.core.permissions import BUILTIN_ROLES
from app.core.security import _fernet
from app.db.session import system_session
from app.domains.audit import service as audit
from app.models import Integration, Organization, Role, RolePermission, User


def grant_super_admin(email: str) -> None:
    with system_session() as db:
        user = db.execute(select(User).where(User.email == email.lower())).scalar_one_or_none()
        if user is None:
            raise SystemExit(f"No user with email {email}")
        role = db.execute(select(Role).where(Role.organization_id == user.organization_id, Role.key == "super_admin")).scalar_one_or_none()
        if role is None:
            name, permissions = BUILTIN_ROLES["super_admin"]
            role = Role(organization_id=user.organization_id, key="super_admin", name=name, is_builtin=True)
            role.permissions = [RolePermission(organization_id=user.organization_id, permission_key=p) for p in sorted(permissions)]
            db.add(role)
            db.flush()
        user.role_id = role.id
        audit.record(db, organization_id=user.organization_id, action="user.super_admin_granted", actor_email="cli", entity_type="user", entity_id=user.id)
    print(f"{email} is now a super administrator")


def verify_audit(slug: str) -> None:
    with system_session() as db:
        org = db.execute(select(Organization).where(Organization.slug == slug)).scalar_one_or_none()
        if org is None:
            raise SystemExit(f"No organization with slug {slug}")
        result = audit.verify_chain(db, org.id)
    print(result)
    raise SystemExit(0 if result["valid"] else 2)


def rotate_secrets() -> None:
    fernet, count = _fernet(), 0
    with system_session() as db:
        for integration in db.execute(select(Integration).where(Integration.credentials_encrypted.isnot(None))).scalars():
            integration.credentials_encrypted = fernet.rotate(integration.credentials_encrypted.encode()).decode()
            count += 1
        for user in db.execute(select(User).where(User.mfa_secret_encrypted.isnot(None))).scalars():
            user.mfa_secret_encrypted = fernet.rotate(user.mfa_secret_encrypted.encode()).decode()
            count += 1
    print(f"Re-encrypted {count} stored secrets with the primary key")


def main() -> None:
    args = sys.argv[1:]
    if args[:1] == ["grant-super-admin"] and len(args) == 2:
        grant_super_admin(args[1])
    elif args[:1] == ["verify-audit"] and len(args) == 2:
        verify_audit(args[1])
    elif args == ["rotate-secrets"]:
        rotate_secrets()
    elif args == ["run-pending"]:
        from app.workers.queue import run_pending

        for job_type, outcome in run_pending(limit=1000):
            print(job_type, outcome)
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
