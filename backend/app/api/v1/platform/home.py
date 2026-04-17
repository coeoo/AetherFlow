from fastapi import APIRouter

from app.config import load_settings
from app.platform.home_summary import collect_home_summary

router = APIRouter(prefix="/api/v1/platform", tags=["platform"])


@router.get("/home-summary")
def home_summary() -> dict[str, object]:
    return {
        "code": 0,
        "message": "success",
        "data": collect_home_summary(load_settings()),
    }
