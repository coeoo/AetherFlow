from sqlalchemy import text

from app.db.session import create_engine_from_url


def test_can_connect_to_postgres(test_database_url: str) -> None:
    engine = create_engine_from_url(test_database_url)

    with engine.connect() as connection:
        assert connection.execute(text("select 1")).scalar() == 1

    engine.dispose()
