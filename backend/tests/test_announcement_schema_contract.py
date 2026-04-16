from app.db.base import Base


def test_announcement_metadata_contains_expected_tables() -> None:
    assert {
        "announcement_sources",
        "announcement_runs",
        "announcement_documents",
        "announcement_intelligence_packages",
    }.issubset(Base.metadata.tables)


def test_announcement_run_has_unique_job_binding() -> None:
    announcement_runs = Base.metadata.tables["announcement_runs"]

    unique_constraint_names = {
        constraint.name for constraint in announcement_runs.constraints
    }

    assert "uq_announcement_runs_job_id" in unique_constraint_names


def test_announcement_document_keeps_source_and_normalized_artifact_refs() -> None:
    announcement_documents = Base.metadata.tables["announcement_documents"]

    column_names = set(announcement_documents.columns.keys())

    assert {
        "source_artifact_id",
        "normalized_text_artifact_id",
        "source_item_key",
        "content_dedup_hash",
    }.issubset(column_names)
