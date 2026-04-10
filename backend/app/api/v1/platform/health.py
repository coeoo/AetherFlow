from fastapi import APIRouter

router = APIRouter(prefix="/api/v1/platform", tags=["platform"])


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
