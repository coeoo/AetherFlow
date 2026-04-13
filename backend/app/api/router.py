from fastapi import APIRouter

from app.api.v1.cve.runs import router as cve_router
from app.api.v1.platform.health import router as platform_router

api_router = APIRouter()
api_router.include_router(cve_router)
api_router.include_router(platform_router)
