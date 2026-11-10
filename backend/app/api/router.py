"""Aggregates all domain routers under /api/v1."""

from fastapi import APIRouter

from app.domains.admin.router import router as admin_router
from app.domains.auth.router import router as auth_router

api_router = APIRouter()
api_router.include_router(auth_router)
api_router.include_router(admin_router)
