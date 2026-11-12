"""Public demo deployments (CTEM_DEMO_MODE=true).

A demo organization with one account per built-in role, all sharing a documented password, and a
sample repository that the platform analyses for real (its findings come from the engines, not
from fixtures). Because the credentials are public, demo mode also removes the ways one visitor
could lock out the others or turn the instance into an open scanner:

* engines that send traffic to targets refuse to run (dry runs still work);
* the demo accounts cannot change password or MFA, cannot be modified by administrators, and are
  never locked out by failed sign-ins;
* organizations cannot be suspended.
"""

import json
import pickle
import uuid
from pathlib import Path

from fastapi import APIRouter
from sqlalchemy import select

from app.core.config import get_settings
from app.core.errors import Forbidden, NotFound
from app.core.security import hash_password
from app.db.base import utcnow
from app.db.session import system_session, tenant_session
from app.models import Organization, User

DEMO_DOMAIN = "demo.example.com"
DEMO_ORG_NAME = "Demo Organization"
SAMPLE_REPO_NAME = "sample-support-bot"

# (role key, email local part, display name, what the role is for)
ACCOUNTS: list[tuple[str, str, str, str]] = [
    ("super_admin", "super.admin", "Demo Super Administrator", "Everything, including the platform operator console"),
    ("org_admin", "org.admin", "Demo Organization Administrator", "Users, roles, organization settings and all security functions"),
    ("security_admin", "security.admin", "Demo Security Administrator", "Scope, integrations, risk policy and all assessments"),
    ("security_analyst", "analyst", "Demo Security Analyst", "Triage findings, run assessments, create remediation tasks"),
    ("vulnerability_manager", "vuln.manager", "Demo Vulnerability Manager", "Vulnerabilities, SLAs, risk acceptance approval"),
    ("cloud_security_engineer", "cloud.engineer", "Demo Cloud Security Engineer", "Cloud posture, cloud integrations, assets"),
    ("red_team_operator", "red.team", "Demo Red Team Operator", "Assessments and AI red teaming"),
    ("auditor", "auditor", "Demo Auditor", "Read everything including the audit log, generate reports"),
    ("read_only", "viewer", "Demo Read-only User", "View inventory, findings and reports"),
]

ACTIVE_DISABLED = ("Active testing is disabled on this public demo, because its sign-in details are published. "
                   "Dry runs show what an engine would do. Deploy your own instance to scan systems you are authorized to test.")


def email_for(local: str) -> str:
    return f"{local}@{DEMO_DOMAIN}"


def is_demo_account(email: str | None) -> bool:
    return bool(email) and get_settings().demo_mode and email.lower().endswith("@" + DEMO_DOMAIN)


def guard_account(email: str | None, action: str = "change this account") -> None:
    """Refuse changes that would lock other visitors out of a shared demo account."""
    if is_demo_account(email):
        raise Forbidden(f"Demo accounts are shared by everyone using this demo, so you cannot {action}.")


def guard_credentials(provided: bool) -> None:
    """Every visitor shares the demo organization, so a stored key or token would be usable by all of them."""
    if provided and get_settings().demo_mode:
        raise Forbidden("The public demo does not store credentials: every visitor shares this organization and could use them. "
                        "Deploy your own instance to connect integrations or Claude.")


def guard_active(active: bool) -> None:
    if active and get_settings().demo_mode:
        raise Forbidden(ACTIVE_DISABLED)


# --- Public description of the demo ---------------------------------------------------------------

router = APIRouter(tags=["demo"])


@router.get("/demo")
def demo_info() -> dict:
    """Sign-in details for the demo accounts. Exists only when demo mode is on."""
    settings = get_settings()
    if not settings.demo_mode:
        raise NotFound("Not found")
    return {
        "enabled": True,
        "password": settings.demo_password,
        "accounts": [{"role": key, "email": email_for(local), "name": name, "purpose": purpose}
                     for key, local, name, purpose in ACCOUNTS],
        "restrictions": [
            "Data is shared by every visitor and is reset when the demo restarts.",
            "Active testing (port, web, API and AI endpoint scans, AI red teaming) is disabled; dry runs work.",
            "Demo accounts cannot change their password or MFA.",
        ],
    }


# --- Seeding ---------------------------------------------------------------------------------------

class _Unsafe:
    """Serialises to a pickle that references os.system, the pattern model scanning flags.
    It is written to disk and disassembled by the platform; nothing ever unpickles it."""

    def __reduce__(self):
        import os

        return (os.system, ("echo never-executed",))


def _write_sample_repo(root: Path) -> None:
    """A small, deliberately insecure AI support bot. Every value in it is synthetic."""
    (root / "src").mkdir(parents=True, exist_ok=True)
    (root / "models").mkdir(exist_ok=True)
    (root / "README.md").write_text(
        "# Sample support bot\n\nGenerated by the CTEM demo seed. Deliberately insecure and not a real application: "
        "old pinned dependencies, a committed provider key in the provider's format (synthetic), a broad MCP "
        "filesystem server, and a model file that references a code-execution callable.\n")
    (root / "requirements.txt").write_text(
        "openai==1.40.0\nlangchain==0.0.200\nrequests==2.19.0\njinja2==2.10\nurllib3==1.24.1\nchromadb==0.3.21\n")
    (root / "package.json").write_text(json.dumps(
        {"name": "sample-support-bot-ui", "version": "1.0.0", "dependencies": {"axios": "0.21.0", "lodash": "4.17.15"}}, indent=2))
    (root / "src" / "agent.py").write_text(
        "import anthropic\nfrom langchain.agents import AgentExecutor\nimport chromadb\n\n"
        "BASE_URL = 'https://api.openai.com/v1'\nLOCAL_MODEL = 'http://gpu-box.internal:11434'\n\n"
        "def build_agent(tools):\n    # tools include refund_order and send_email; no approval step\n"
        "    return AgentExecutor(tools=tools)\n")
    (root / ".env").write_text("ANTHROPIC_API_KEY=sk-ant-api03-" + "Zk9" * 32 + "\n")  # synthetic, provider format
    (root / ".mcp.json").write_text(json.dumps({"mcpServers": {
        "files": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"]},
        "crm": {"url": "http://crm-mcp.sample.invalid/mcp", "env": {"CRM_API_TOKEN": "tok_live_" + "0a1b2c3d4e" * 2}},
        "pinned": {"command": "npx", "args": ["-y", "@sample/mcp-server@1.4.2"], "env": {"API_KEY": "${SAMPLE_KEY}"}},
    }}, indent=2))
    # Writing sample model files for the scanner to find; nothing in the platform ever unpickles them.
    (root / "models" / "classifier.pkl").write_bytes(pickle.dumps(_Unsafe()))  # nosemgrep: python.lang.security.deserialization.pickle.avoid-pickle
    (root / "models" / "scaler.pkl").write_bytes(pickle.dumps({"mean": [0.1, 0.2], "scale": [1.0, 2.0]}))  # nosemgrep: python.lang.security.deserialization.pickle.avoid-pickle


def seed() -> dict:
    """Create the demo organization, accounts and sample assessments. Safe to run repeatedly."""
    settings = get_settings()
    if not settings.demo_mode:
        raise SystemExit("Refusing to seed demo accounts: CTEM_DEMO_MODE is not enabled")
    from app.core.permissions import BUILTIN_ROLES
    from app.domains.auth.service import create_builtin_roles
    from app.domains.policy.service import install_default_policies
    from app.models import Role, RolePermission

    with system_session() as db:
        org = db.execute(select(Organization).where(Organization.name == DEMO_ORG_NAME)).scalar_one_or_none()
        created_org = org is None
        if org is None:
            org = Organization(name=DEMO_ORG_NAME, slug="demo")
            db.add(org)
            db.flush()
            roles = create_builtin_roles(db, org.id)
            install_default_policies(db, org.id)
        else:
            roles = {r.key: r for r in db.execute(select(Role).where(Role.organization_id == org.id)).scalars()}
        if "super_admin" not in roles:
            name, permissions = BUILTIN_ROLES["super_admin"]
            role = Role(organization_id=org.id, key="super_admin", name=name, is_builtin=True)
            role.permissions = [RolePermission(organization_id=org.id, permission_key=p) for p in sorted(permissions)]
            db.add(role)
            db.flush()
            roles["super_admin"] = role
        password_hash = hash_password(settings.demo_password)
        for key, local, name, _ in ACCOUNTS:
            email = email_for(local)
            user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
            if user is None:
                user = User(organization_id=org.id, email=email, full_name=name, password_hash=password_hash, role_id=roles[key].id)
                db.add(user)
            # Restore anything a visitor may have changed before the guards existed or by other means.
            user.password_hash, user.role_id, user.is_active = password_hash, roles[key].id, True
            user.mfa_enabled, user.mfa_secret_encrypted = False, None
            user.failed_login_count, user.locked_until = 0, None
            user.email_verified_at = user.email_verified_at or utcnow()
        org.is_active = True
        org_id = org.id

    if created_org and settings.demo_sample_data:
        _seed_sample_data(org_id)
    return {"organization_id": str(org_id), "created": created_org, "accounts": len(ACCOUNTS)}


def _seed_sample_data(org_id: uuid.UUID) -> None:
    from app.domains.assessments.service import start_run
    from app.models import Assessment, AssessmentTarget, ScopeTarget
    from app.workers.queue import enqueue

    settings = get_settings()
    if not settings.repo_scan_root:
        raise SystemExit("Set CTEM_REPO_SCAN_ROOT so the sample repository can be analysed")
    root = Path(settings.repo_scan_root).resolve() / SAMPLE_REPO_NAME
    _write_sample_repo(root)
    note = "Demo seed: generated sample repository on this instance"
    with tenant_session(org_id) as db:
        db.add(ScopeTarget(organization_id=org_id, kind="path", value=str(root), allow_active=False, authorization_note=note))
        db.flush()
        assessment = Assessment(organization_id=org_id, name="Sample support bot: AI, secrets and dependency analysis",
                                kind="repository_analysis", config={})
        db.add(assessment)
        db.flush()
        db.add(AssessmentTarget(organization_id=org_id, assessment_id=assessment.id, kind="path", value=str(root)))
        db.flush()
        start_run(db, assessment, None)
        # Public threat intelligence, so vulnerabilities show KEV and EPSS context and AI findings link to ATLAS.
        feeds = [s.strip() for s in settings.demo_intel_sources.split(",") if s.strip()]
        if feeds:
            enqueue(db, organization_id=org_id, job_type="intel.sync", config={"sources": feeds}, idempotency_key="intel.sync:demo-seed")

