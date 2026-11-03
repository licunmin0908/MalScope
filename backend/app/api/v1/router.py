"""API v1 聚合路由。"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import analysis, audit, auth, dashboard, iocs, reports, rules, samples, users

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(dashboard.router)
api_router.include_router(samples.router)
api_router.include_router(analysis.router)
api_router.include_router(iocs.router)
api_router.include_router(reports.router)
api_router.include_router(rules.router)
api_router.include_router(users.router)
api_router.include_router(audit.router)
