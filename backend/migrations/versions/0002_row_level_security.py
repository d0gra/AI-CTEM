"""Row-level security, application role grants, permission catalogue.

Revision ID: 0002
Revises: 0001

Tenant isolation model
----------------------
Every tenant-owned table has RLS enabled and forced. A row is visible/writable when its
organization_id equals the transaction-local setting ``app.current_org`` or when the
transaction is an explicit system context (``app.system = 'on'``). The application role is a
non-owner role without BYPASSRLS. ``audit_events`` is append-only for the application role.
"""
import os

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

APP_ROLE = os.environ.get("CTEM_APP_DB_ROLE", "ctem_app")

TENANT_TABLES = [
    "ai_agents", "ai_assessment_tests", "ai_assessments", "ai_assets", "ai_findings", "ai_integrations",
    "ai_models", "ai_usage", "assessment_runs", "assessment_targets", "assessments",
    "asset_discovery_events", "asset_relationships", "assets", "attack_path_edges", "attack_path_nodes",
    "attack_paths", "audit_events", "evidence", "finding_events", "findings", "integrations", "jobs",
    "mcp_servers", "notification_deliveries", "notification_reads", "notification_rules", "notifications",
    "policies", "policy_evaluations", "policy_exceptions", "remediation_tasks", "reports",
    "risk_acceptances", "risk_scores", "role_permissions", "roles", "scope_targets", "sessions",
    "team_members", "teams", "user_tokens", "users",
]
GLOBAL_TABLES = ["organizations", "permissions", "vulnerabilities", "threat_intelligence", "intel_sync_state"]

PREDICATE = (
    "organization_id = nullif(current_setting('app.current_org', true), '')::uuid "
    "OR current_setting('app.system', true) = 'on'"
)

PERMISSIONS = {
    "assets:read": "View assets, relationships and discovery history",
    "assets:write": "Create, edit and retire assets",
    "scope:manage": "Manage authorized assessment scope",
    "discovery:run": "Run asset discovery",
    "findings:read": "View findings and evidence",
    "findings:write": "Triage, assign and update findings",
    "assessments:read": "View assessments and runs",
    "assessments:run": "Create and run security assessments",
    "ai:read": "View AI asset inventory and AI findings",
    "ai:write": "Manage AI asset inventory and approvals",
    "ai_redteam:run": "Authorize and run AI red team assessments",
    "intel:read": "View threat intelligence",
    "intel:sync": "Trigger threat intelligence synchronisation",
    "attack_paths:read": "View attack paths",
    "attack_paths:compute": "Recompute attack paths",
    "risk:read": "View risk scores and acceptances",
    "risk:request": "Request risk acceptance",
    "risk:approve": "Approve or reject risk acceptance and policy exceptions",
    "risk:configure": "Configure risk policy",
    "remediation:read": "View remediation tasks",
    "remediation:write": "Manage remediation tasks",
    "policies:read": "View policies and evaluations",
    "policies:manage": "Manage policies",
    "integrations:read": "View integrations",
    "integrations:manage": "Configure integrations and credentials",
    "reports:read": "View and download reports",
    "reports:generate": "Generate reports",
    "notifications:manage": "Manage notification rules",
    "audit:read": "View audit logs",
    "admin:users": "Manage users, teams and roles",
    "admin:org": "Manage organization settings",
    "ai_analytics:use": "Use AI-assisted analysis",
    "platform:admin": "Cross-organization platform administration",
}


def upgrade() -> None:
    op.execute(
        f"""DO $$ BEGIN
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
            RAISE EXCEPTION 'Application role {APP_ROLE} does not exist. Create it before migrating '
                            '(see docs/deployment.md) or set CTEM_APP_DB_ROLE.';
        END IF; END $$"""
    )
    op.execute(f"GRANT USAGE ON SCHEMA public TO {APP_ROLE}")
    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(f"CREATE POLICY tenant_isolation ON {table} USING ({PREDICATE}) WITH CHECK ({PREDICATE})")
        if table == "audit_events":
            op.execute(f"GRANT SELECT, INSERT ON {table} TO {APP_ROLE}")
        else:
            op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO {APP_ROLE}")
    for table in GLOBAL_TABLES:
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO {APP_ROLE}")
    # Organizations are created at registration and never deleted by the application role.
    op.execute(f"REVOKE DELETE ON organizations FROM {APP_ROLE}")
    op.execute(f"REVOKE INSERT, UPDATE, DELETE ON permissions FROM {APP_ROLE}")
    for key, description in PERMISSIONS.items():
        op.execute(
            "INSERT INTO permissions (key, description) VALUES ('%s', '%s')" % (key, description.replace("'", "''"))
        )


def downgrade() -> None:
    op.execute("DELETE FROM permissions")
    for table in TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
        op.execute(f"REVOKE ALL ON {table} FROM {APP_ROLE}")
    for table in GLOBAL_TABLES:
        op.execute(f"REVOKE ALL ON {table} FROM {APP_ROLE}")
