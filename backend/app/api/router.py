from fastapi import APIRouter
from app.api.v1.announcements.monitor_runs import router as announcement_monitor_runs_router
from app.api.v1.announcements.runs import router as announcement_runs_router
from app.api.v1.announcements.sources import router as announcement_sources_router

from app.api.v1.cve.runs import router as cve_router
from app.api.v1.platform.artifacts import router as artifacts_router
from app.api.v1.platform.deliveries import router as platform_deliveries_router
from app.api.v1.platform.health import router as platform_router

api_router = APIRouter()
api_router.include_router(announcement_monitor_runs_router)
api_router.include_router(announcement_runs_router)
api_router.include_router(announcement_sources_router)
api_router.include_router(cve_router)
api_router.include_router(platform_router)
api_router.include_router(platform_deliveries_router)
api_router.include_router(artifacts_router)
