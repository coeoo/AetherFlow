from app.db.session import create_engine_from_url, create_session_factory


def test_create_engine_from_url_reuses_same_engine_for_same_database_url(
    test_database_url: str,
) -> None:
    first = create_engine_from_url(test_database_url)
    second = create_engine_from_url(test_database_url)

    assert first is second


def test_create_session_factory_reuses_same_factory_for_same_database_url(
    test_database_url: str,
) -> None:
    first = create_session_factory(test_database_url)
    second = create_session_factory(test_database_url)

    assert first is second
