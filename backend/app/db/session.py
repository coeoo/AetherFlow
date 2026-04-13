from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker


@lru_cache(maxsize=None)
def create_engine_from_url(database_url: str) -> Engine:
    return create_engine(
        database_url,
        future=True,
        pool_pre_ping=True,
    )


@lru_cache(maxsize=None)
def create_session_factory(database_url: str) -> sessionmaker[Session]:
    return sessionmaker(
        bind=create_engine_from_url(database_url),
        autoflush=False,
        expire_on_commit=False,
    )
