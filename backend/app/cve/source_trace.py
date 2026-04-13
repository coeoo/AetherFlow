from __future__ import annotations

from app.models import SourceFetchRecord


def record_source_fetch(
    session,
    *,
    run,
    source_type: str,
    source_ref: str | None,
    status: str,
    request_snapshot: dict[str, object],
    response_meta: dict[str, object] | None = None,
    error_message: str | None = None,
) -> SourceFetchRecord:
    record = SourceFetchRecord(
        scene_name="cve",
        source_id=run.run_id,
        source_type=source_type,
        source_ref=source_ref,
        status=status,
        request_snapshot_json=request_snapshot,
        response_meta_json=response_meta or {},
        error_message=error_message,
    )
    session.add(record)
    session.flush()
    return record
