from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker


def create_engine_from_url(database_url: str) -> Engine:
    return create_engine(
        database_url,
        future=True,
        pool_pre_ping=True,
    )


def create_session_factory(database_url: str) -> sessionmaker[Session]:
    return sessionmaker(
        bind=create_engine_from_url(database_url),
        autoflush=False,
        expire_on_commit=False,
    )
