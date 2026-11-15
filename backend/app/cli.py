"""Operational commands.

    python -m app.cli create-organization <name> <admin-email> [--name <full name>]
                                                  create an organization and its administrator, and print a
                                                  one-time link for the administrator to set a password
    python -m app.cli grant-super-admin <email>  promote an existing user to the platform super administrator role
    python -m app.cli verify-audit <org-slug>     recompute an organization's audit hash chain
    python -m app.cli rotate-secrets              re-encrypt stored secrets with the first key in CTEM_ENCRYPTION_KEYS
    python -m app.cli run-pending                 execute queued jobs once in this process (no scheduler)
    python -m app.cli seed-demo                   create the demo organization and its accounts (CTEM_DEMO_MODE=true only)
    python -m app.cli purge-expired               apply the retention periods now, for every organization
    python -m app.cli export-organization <org-slug> <file.json>
                                                  write everything stored for an organization, without credentials
    python -m app.cli delete-organization <org-slug> --confirm <org-slug>
                                                  permanently delete an organization and all of its data
"""

import sys

from sqlalchemy import select

import app.api.router  # noqa: F401  (registers engines and job handlers)
from app.core.permissions import BUILTIN_ROLES
from app.core.security import _fernet
from app.db.session import system_session
from app.domains.audit import service as audit
from app.models import Integration, Organization, Role, RolePermission, User


def create_organization_cmd(name: str, email: str, full_name: str | None) -> None:
    """The first organization on an installation where self-service registration is off. The
    administrator sets a password through a one-time link, valid for 7 days, which is printed here and
    also emailed when SMTP is configured."""
    from app.core.config import get_settings
    from app.core.errors import Conflict
    from app.core.security import hash_password, new_token
    from app.domains.auth.service import create_organization, issue_invitation

    email = email.lower().strip()
    if not name.strip() or "@" not in email:
        raise SystemExit("Usage: create-organization <organization name> <admin email> [--name <full name>]")
    with system_session() as db:
        try:
            # No usable password until the link is followed: a random one that nobody knows.
            user = create_organization(db, organization_name=name, email=email, full_name=full_name or email.split("@")[0],
                                       password_hash=hash_password(new_token(32)))
        except Conflict:
            raise SystemExit(f"A user with email {email} already exists") from None
        org_id = user.organization_id
        slug = db.execute(select(Organization.slug).where(Organization.id == org_id)).scalar_one()
        audit.record(db, organization_id=org_id, action="organization.created", actor_email="cli",
                     entity_type="organization", entity_id=org_id, data={"administrator": email})
        link = issue_invitation(db, user)
    print(f"Created organization {name.strip()} ({slug}) with administrator {email}.")
    print(f"Set the administrator's password within 7 days at:\n\n  {link}\n")
    base = get_settings().public_base_url
    if base.startswith("http://localhost"):
        print(f"The link uses CTEM_PUBLIC_BASE_URL ({base}); set it to the platform's real address if that is wrong.")


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


EXPORT_SKIPPED_TABLES = {"sessions", "user_tokens", "api_tokens"}  # live credentials: of no use in an export
EXPORT_REDACTED_COLUMNS = {"password_hash", "mfa_secret_encrypted", "credentials_encrypted", "canary_token"}


def _organization(db, slug: str) -> Organization:
    org = db.execute(select(Organization).where(Organization.slug == slug)).scalar_one_or_none()
    if org is None:
        raise SystemExit(f"No organization with slug {slug}")
    return org


def purge_expired() -> None:
    from app.domains.platform.retention import purge

    with system_session() as db:
        for org in db.execute(select(Organization)).scalars():
            print(org.slug, purge(db, org.id) or "nothing to remove")


def export_organization(slug: str, path: str) -> None:
    """Every row the organization owns, table by table, as JSON. Uploaded files are listed by key, not embedded."""
    import json

    from app.db.base import Base

    with system_session() as db, open(path, "w", encoding="utf-8") as out:
        org = _organization(db, slug)
        out.write(json.dumps({"organization": {"id": str(org.id), "slug": org.slug, "name": org.name}})[:-1] + ', "tables": {')
        first, total = True, 0
        for table in Base.metadata.sorted_tables:
            if "organization_id" not in table.c or table.name in EXPORT_SKIPPED_TABLES:
                continue
            out.write(("" if first else ",") + f"\n{json.dumps(table.name)}: [")
            first = False
            columns = [c for c in table.columns if c.name not in EXPORT_REDACTED_COLUMNS]
            rows = db.execute(select(*columns).where(table.c.organization_id == org.id)).mappings()
            for i, row in enumerate(rows):
                out.write(("," if i else "") + "\n" + json.dumps(dict(row), default=str))
                total += 1
            out.write("]")
        out.write("\n}}\n")
        audit.record(db, organization_id=org.id, action="organization.exported", actor_email="cli", data={"rows": total})
    print(f"Wrote {total} rows for {slug} to {path}")


def delete_organization(slug: str, confirm: str) -> None:
    """Removes the organization and, by cascade, every row it owns, then its stored files. Not reversible.

    Runs as the schema owner (CTEM_MIGRATION_DATABASE_URL): the application role cannot delete an
    organization or any audit record, by design."""
    from sqlalchemy import create_engine, text

    from app.core import storage
    from app.core.config import get_settings
    from app.models import Assessment, Evidence, Report

    if confirm != slug:
        raise SystemExit("Refusing: --confirm must repeat the organization's slug")
    with system_session() as db:
        org = _organization(db, slug)
        org_id = org.id
        keys = set(db.execute(select(Evidence.storage_key).where(Evidence.organization_id == org_id, Evidence.storage_key.isnot(None))).scalars())
        keys |= set(db.execute(select(Report.storage_key).where(Report.organization_id == org_id, Report.storage_key.isnot(None))).scalars())
        keys |= {a.config["storage_key"] for a in db.execute(select(Assessment).where(Assessment.organization_id == org_id)).scalars()
                 if (a.config or {}).get("storage_key")}
    owner = create_engine(get_settings().migration_database_url)
    try:
        with owner.begin() as conn:
            conn.execute(text("select set_config('app.system', 'on', true)"))
            conn.execute(text("delete from organizations where id = :id"), {"id": org_id})
    finally:
        owner.dispose()
    failed = 0
    for key in keys:
        try:
            storage.get_storage().delete(key)
        except Exception:  # noqa: BLE001  (report the count; the database rows are already gone)
            failed += 1
    print(f"Deleted organization {slug} and {len(keys) - failed} stored files" + (f"; {failed} files could not be removed" if failed else ""))


def main() -> None:
    args = sys.argv[1:]
    if args[:1] == ["create-organization"] and len(args) in (3, 5) and (len(args) == 3 or args[3] == "--name"):
        create_organization_cmd(args[1], args[2], args[4] if len(args) == 5 else None)
    elif args[:1] == ["grant-super-admin"] and len(args) == 2:
        grant_super_admin(args[1])
    elif args[:1] == ["verify-audit"] and len(args) == 2:
        verify_audit(args[1])
    elif args == ["rotate-secrets"]:
        rotate_secrets()
    elif args == ["purge-expired"]:
        purge_expired()
    elif args[:1] == ["export-organization"] and len(args) == 3:
        export_organization(args[1], args[2])
    elif args[:1] == ["delete-organization"] and len(args) == 4 and args[2] == "--confirm":
        delete_organization(args[1], args[3])
    elif args == ["seed-demo"]:
        from app.domains.demo import seed

        print(seed())
    elif args == ["run-pending"]:
        from app.workers.queue import run_pending

        for job_type, outcome in run_pending(limit=1000):
            print(job_type, outcome)
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
