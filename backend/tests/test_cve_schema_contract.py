from app.db.base import Base


def test_cve_metadata_contains_runtime_tables() -> None:
    assert "cve_runs" in Base.metadata.tables
    assert "cve_patch_artifacts" in Base.metadata.tables


def test_cve_runs_has_unique_job_id() -> None:
    cve_runs = Base.metadata.tables["cve_runs"]
    constraint_names = {constraint.name for constraint in cve_runs.constraints}
    assert "uq_cve_runs_job_id" in constraint_names


def test_cve_patch_artifacts_links_to_artifacts() -> None:
    patches = Base.metadata.tables["cve_patch_artifacts"]
    assert "artifact_id" in patches.c
