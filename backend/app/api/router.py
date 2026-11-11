"""Aggregates all domain routers under /api/v1."""

from fastapi import APIRouter

import app.engines.registry  # noqa: F401  (registers assessment engines and job handlers)
from app.domains.admin.router import router as admin_router
from app.domains.ai.router import router as ai_router
from app.domains.assessments.router import router as assessments_router
from app.domains.assets.router import router as assets_router
from app.domains.attack_paths.router import router as attack_paths_router
from app.domains.audit.router import router as audit_router
from app.domains.auth.router import router as auth_router
from app.domains.dashboard.router import router as dashboard_router
from app.domains.findings.router import router as findings_router
from app.domains.integrations.router import router as integrations_router
from app.domains.intel.router import router as intel_router
from app.domains.notifications.router import router as notifications_router
from app.domains.policy.router import router as policy_router
from app.domains.remediation.router import router as remediation_router
from app.domains.risk.router import router as risk_router

api_router = APIRouter()
for _router in (
    auth_router, admin_router, assets_router, findings_router, assessments_router, attack_paths_router,
    risk_router, remediation_router, policy_router, integrations_router, intel_router, notifications_router,
    dashboard_router, audit_router, ai_router,
):
    api_router.include_router(_router)
