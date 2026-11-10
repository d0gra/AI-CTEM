"""Permission catalogue and built-in role definitions.

Permissions are code-defined (they gate code paths); roles are data and can be customised
per organization. Built-in roles are created for every new organization.
"""

PERMISSIONS: dict[str, str] = {
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

_ALL = set(PERMISSIONS) - {"platform:admin"}
_READ = {p for p in PERMISSIONS if p.endswith(":read")}

BUILTIN_ROLES: dict[str, tuple[str, set[str]]] = {
    "super_admin": ("Super Administrator", set(PERMISSIONS)),
    "org_admin": ("Organization Administrator", _ALL),
    "security_admin": ("Security Administrator", _ALL - {"admin:org", "admin:users"}),
    "security_analyst": (
        "Security Analyst",
        _READ
        | {"findings:write", "discovery:run", "assessments:run", "remediation:write", "risk:request",
           "reports:generate", "attack_paths:compute", "ai_analytics:use"},
    ),
    "vulnerability_manager": (
        "Vulnerability Manager",
        _READ
        | {"findings:write", "assessments:run", "remediation:write", "risk:request", "risk:approve",
           "reports:generate", "intel:sync", "ai_analytics:use"},
    ),
    "cloud_security_engineer": (
        "Cloud Security Engineer",
        _READ
        | {"findings:write", "assets:write", "discovery:run", "assessments:run", "remediation:write",
           "risk:request", "integrations:manage", "reports:generate"},
    ),
    "red_team_operator": (
        "Red Team Operator",
        _READ
        | {"assessments:run", "ai_redteam:run", "discovery:run", "findings:write", "attack_paths:compute",
           "reports:generate"},
    ),
    "auditor": ("Auditor", _READ | {"audit:read", "reports:generate"}),
    "read_only": ("Read-only User", _READ - {"audit:read", "integrations:read"}),
}
