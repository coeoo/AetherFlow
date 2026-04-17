from __future__ import annotations

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import AnnouncementRun, AnnouncementSource, SourceFetchRecord, TaskJob


def create_announcement_run(
    session: Session,
    *,
    input_mode: str,
    source_url: str,
) -> AnnouncementRun:
    if input_mode != "url":
        raise ValueError(f"暂不支持的公告输入模式: {input_mode}")

    job = TaskJob(
        scene_name="announcement",
        job_type="announcement_manual_extract",
        trigger_kind="manual",
        status="queued",
        payload_json={
            "input_mode": input_mode,
            "source_url": source_url,
        },
    )
    session.add(job)
    session.flush()

    run = AnnouncementRun(
        job_id=job.job_id,
        entry_mode="manual_url",
        status="queued",
        stage="fetch_source",
        input_snapshot_json={
            "input_mode": input_mode,
            "source_url": source_url,
        },
        summary_json={},
    )
    session.add(run)
    session.flush()
    return run


def list_announcement_sources(session: Session) -> list[AnnouncementSource]:
    return list(
        session.execute(
            select(AnnouncementSource).order_by(
                AnnouncementSource.created_at,
                AnnouncementSource.source_id,
            )
        ).scalars()
    )


def create_run_now_job(
    session: Session,
    *,
    source_id,
) -> TaskJob | None:
    source = session.get(AnnouncementSource, source_id)
    if source is None:
        return None

    job = TaskJob(
        scene_name="announcement",
        job_type="announcement_monitor_fetch",
        trigger_kind="manual",
        status="queued",
        payload_json={
            "source_id": str(source.source_id),
        },
    )
    session.add(job)
    session.flush()
    return job


def list_monitor_runs(session: Session) -> list[dict[str, object]]:
    extraction_run_counts = (
        select(
            AnnouncementRun.trigger_fetch_id.label("fetch_id"),
            func.count(AnnouncementRun.run_id).label("extraction_run_count"),
        )
        .where(AnnouncementRun.trigger_fetch_id.is_not(None))
        .group_by(AnnouncementRun.trigger_fetch_id)
        .subquery()
    )

    rows = session.execute(
        select(
            SourceFetchRecord,
            AnnouncementSource,
            func.coalesce(extraction_run_counts.c.extraction_run_count, 0),
        )
        .outerjoin(
            AnnouncementSource,
            AnnouncementSource.source_id == SourceFetchRecord.source_id,
        )
        .outerjoin(
            extraction_run_counts,
            extraction_run_counts.c.fetch_id == SourceFetchRecord.fetch_id,
        )
        .where(SourceFetchRecord.scene_name == "announcement")
        .order_by(SourceFetchRecord.created_at.desc(), SourceFetchRecord.fetch_id.desc())
    ).all()

    return [
        _serialize_monitor_run_summary(
            fetch_record=fetch_record,
            source=source,
            extraction_run_count=int(extraction_run_count or 0),
        )
        for fetch_record, source, extraction_run_count in rows
    ]


def get_monitor_run_detail(
    session: Session,
    *,
    fetch_id: UUID,
) -> dict[str, object] | None:
    row = session.execute(
        select(SourceFetchRecord, AnnouncementSource)
        .outerjoin(
            AnnouncementSource,
            AnnouncementSource.source_id == SourceFetchRecord.source_id,
        )
        .where(
            SourceFetchRecord.fetch_id == fetch_id,
            SourceFetchRecord.scene_name == "announcement",
        )
    ).one_or_none()
    if row is None:
        return None

    fetch_record, source = row
    triggered_runs = list(
        session.execute(
            select(AnnouncementRun)
            .where(AnnouncementRun.trigger_fetch_id == fetch_record.fetch_id)
            .order_by(AnnouncementRun.created_at.desc(), AnnouncementRun.run_id.desc())
        ).scalars()
    )

    return {
        **_serialize_monitor_run_summary(
            fetch_record=fetch_record,
            source=source,
            extraction_run_count=len(triggered_runs),
        ),
        "error_message": fetch_record.error_message,
        "request_snapshot": dict(fetch_record.request_snapshot_json or {}),
        "triggered_runs": [
            {
                "run_id": str(run.run_id),
                "entry_mode": run.entry_mode,
                "status": run.status,
                "stage": run.stage,
                "title_hint": run.title_hint,
                "source_url": str((run.input_snapshot_json or {}).get("source_url") or "") or None,
                "summary": dict(run.summary_json or {}),
                "created_at": run.created_at.isoformat(),
            }
            for run in triggered_runs
        ],
    }


def _serialize_monitor_run_summary(
    *,
    fetch_record: SourceFetchRecord,
    source: AnnouncementSource | None,
    extraction_run_count: int,
) -> dict[str, object]:
    request_snapshot = dict(fetch_record.request_snapshot_json or {})
    response_meta = dict(fetch_record.response_meta_json or {})

    return {
        "fetch_id": str(fetch_record.fetch_id),
        "source_id": str(fetch_record.source_id) if fetch_record.source_id is not None else None,
        "source_name": _get_monitor_source_name(fetch_record=fetch_record, source=source),
        "source_type": _get_monitor_source_type(fetch_record=fetch_record, source=source),
        "status": fetch_record.status,
        "discovered_count": int(response_meta.get("discovered_count") or 0),
        "new_count": int(response_meta.get("new_count") or 0),
        "extraction_run_count": extraction_run_count,
        "created_at": fetch_record.created_at.isoformat(),
    }


def _get_monitor_source_name(
    *,
    fetch_record: SourceFetchRecord,
    source: AnnouncementSource | None,
) -> str:
    if source is not None:
        return source.name
    if fetch_record.source_ref:
        return fetch_record.source_ref
    return "未命名监控源"


def _get_monitor_source_type(
    *,
    fetch_record: SourceFetchRecord,
    source: AnnouncementSource | None,
) -> str:
    if source is not None:
        return source.source_type
    source_type = (fetch_record.request_snapshot_json or {}).get("source_type")
    if source_type:
        return str(source_type)
    return fetch_record.source_type
