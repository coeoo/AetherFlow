from fastapi import APIRouter

from app.config import load_settings
from app.platform.health_summary import collect_health_summary

router = APIRouter(prefix="/api/v1/platform", tags=["platform"])


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/health/summary")
def health_summary() -> dict[str, object]:
    return collect_health_summary(load_settings())
