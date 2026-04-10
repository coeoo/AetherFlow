from fastapi import FastAPI

from app.api.router import api_router
from app.config import load_settings


def create_app() -> FastAPI:
    settings = load_settings()
    app = FastAPI(title=settings.app_name)
    app.include_router(api_router)
    return app


app = create_app()
