from pathlib import Path
import uuid

from sqlalchemy import select

from app.models import (
    AnnouncementDocument,
    AnnouncementIntelligencePackage,
    AnnouncementRun,
    AnnouncementSource,
    SourceFetchRecord,
    TaskAttempt,
    TaskJob,
)
from app.db.session import create_session_factory
from app.worker.runtime import process_once


def test_worker_processes_manual_announcement_run_and_creates_document_and_package(
    db_session, test_database_url, monkeypatch, tmp_path
) -> None:
    monkeypatch.setenv("AETHERFLOW_ARTIFACT_ROOT", str(tmp_path))
    monkeypatch.setattr(
        "app.announcements.runtime.fetch_url_content",
        lambda url: "<html><body>OpenSSL vulnerability for Linux systems</body></html>",
    )

    job = TaskJob(
        scene_name="announcement",
        job_type="announcement_manual_extract",
        trigger_kind="manual",
        status="queued",
        payload_json={
            "input_mode": "url",
            "source_url": "https://example.com/advisory",
        },
    )
    db_session.add(job)
    db_session.flush()

    run = AnnouncementRun(
        job_id=job.job_id,
        entry_mode="manual_url",
        status="queued",
        stage="fetch_source",
        input_snapshot_json={
            "input_mode": "url",
            "source_url": "https://example.com/advisory",
        },
        summary_json={},
    )
    db_session.add(run)
    db_session.commit()

    session_factory = create_session_factory(test_database_url)
    processed = process_once(session_factory, worker_name="worker-announcement")

    assert processed is True

    db_session.expire_all()
    reloaded_run = db_session.get(AnnouncementRun, run.run_id)
    assert reloaded_run is not None
    assert reloaded_run.status == "succeeded"
    assert reloaded_run.stage == "finalize_run"
    assert reloaded_run.summary_json["linux_related"] is True

    document = db_session.execute(
        select(AnnouncementDocument).where(AnnouncementDocument.run_id == run.run_id)
    ).scalar_one()
    assert document.source_url == "https://example.com/advisory"
    assert document.source_artifact_id is not None
    assert document.normalized_text_artifact_id is not None
    assert "OpenSSL" in (document.content_excerpt or "")

    package = db_session.execute(
        select(AnnouncementIntelligencePackage).where(
            AnnouncementIntelligencePackage.run_id == run.run_id
        )
    ).scalar_one()
    assert float(package.confidence) >= 0.6
    assert package.notify_recommended is True
    assert "Linux" in package.analyst_summary

    attempt = db_session.execute(
        select(TaskAttempt).where(TaskAttempt.job_id == job.job_id)
    ).scalar_one()
    assert attempt.status == "succeeded"


def test_worker_processes_openwall_monitor_job_and_creates_fetch_record_and_runs(
    db_session, test_database_url, monkeypatch
) -> None:
    source = AnnouncementSource(
        source_id=uuid.uuid4(),
        name="Openwall OSS Security",
        source_type="openwall",
        enabled=True,
        schedule_cron="0 */2 * * *",
        config_json={"days_back": 3, "max_documents": 5},
        delivery_policy_json={},
    )
    db_session.add(source)
    db_session.flush()

    job = TaskJob(
        scene_name="announcement",
        job_type="announcement_monitor_fetch",
        trigger_kind="manual",
        status="queued",
        payload_json={"source_id": str(source.source_id)},
    )
    db_session.add(job)
    db_session.commit()

    monkeypatch.setattr(
        "app.announcements.runtime.load_source_documents",
        lambda session, *, source: [
            {
                "source_name": "Openwall",
                "source_type": "openwall",
                "title": "OpenSSL advisory",
                "source_url": "https://www.openwall.com/lists/oss-security/2026/04/15/42",
                "published_at": "2026-04-15T09:00:00+00:00",
                "source_item_key": "https://www.openwall.com/lists/oss-security/2026/04/15/42",
                "raw_content": "OpenSSL Linux vulnerability details",
                "content_dedup_hash": "a" * 64,
            }
        ],
    )

    session_factory = create_session_factory(test_database_url)
    processed = process_once(session_factory, worker_name="worker-announcement")

    assert processed is True

    db_session.expire_all()
    fetch_record = db_session.execute(
        select(SourceFetchRecord).where(
            SourceFetchRecord.scene_name == "announcement",
            SourceFetchRecord.source_id == source.source_id,
        )
    ).scalar_one()
    assert fetch_record.status == "succeeded"
    assert fetch_record.response_meta_json["discovered_count"] == 1
    assert fetch_record.response_meta_json["new_count"] == 1

    run = db_session.execute(
        select(AnnouncementRun).where(AnnouncementRun.trigger_fetch_id == fetch_record.fetch_id)
    ).scalar_one()
    assert run.entry_mode == "monitor_source"
    assert run.source_id == source.source_id
    assert run.status == "queued"
    assert run.title_hint == "OpenSSL advisory"


def test_worker_does_not_create_duplicate_runs_for_same_source_item_key(
    db_session, test_database_url, monkeypatch
) -> None:
    source = AnnouncementSource(
        source_id=uuid.uuid4(),
        name="Openwall OSS Security",
        source_type="openwall",
        enabled=True,
        schedule_cron="0 */2 * * *",
        config_json={"days_back": 3, "max_documents": 5},
        delivery_policy_json={},
    )
    db_session.add(source)
    db_session.flush()

    existing_job = TaskJob(
        scene_name="announcement",
        job_type="announcement_manual_extract",
        trigger_kind="manual",
        status="queued",
        payload_json={"source_url": "https://www.openwall.com/lists/oss-security/2026/04/15/42"},
    )
    db_session.add(existing_job)
    db_session.flush()

    existing_run = AnnouncementRun(
        job_id=existing_job.job_id,
        entry_mode="monitor_source",
        source_id=source.source_id,
        status="queued",
        stage="fetch_source",
        title_hint="OpenSSL advisory",
        input_snapshot_json={
            "source_item_key": "https://www.openwall.com/lists/oss-security/2026/04/15/42",
            "source_url": "https://www.openwall.com/lists/oss-security/2026/04/15/42",
        },
        summary_json={},
    )
    db_session.add(existing_run)
    db_session.flush()

    existing_document = AnnouncementDocument(
        run_id=existing_run.run_id,
        source_id=source.source_id,
        title="OpenSSL advisory",
        source_name="Openwall",
        source_url="https://www.openwall.com/lists/oss-security/2026/04/15/42",
        source_item_key="https://www.openwall.com/lists/oss-security/2026/04/15/42",
        content_dedup_hash="b" * 64,
    )
    db_session.add(existing_document)
    db_session.flush()

    job = TaskJob(
        scene_name="announcement",
        job_type="announcement_monitor_fetch",
        trigger_kind="manual",
        status="queued",
        payload_json={"source_id": str(source.source_id)},
    )
    db_session.add(job)
    db_session.commit()

    monkeypatch.setattr(
        "app.announcements.runtime.load_source_documents",
        lambda session, *, source: [
            {
                "source_name": "Openwall",
                "source_type": "openwall",
                "title": "OpenSSL advisory",
                "source_url": "https://www.openwall.com/lists/oss-security/2026/04/15/42",
                "published_at": "2026-04-15T09:00:00+00:00",
                "source_item_key": "https://www.openwall.com/lists/oss-security/2026/04/15/42",
                "raw_content": "OpenSSL Linux vulnerability details",
                "content_dedup_hash": "a" * 64,
            }
        ],
    )

    session_factory = create_session_factory(test_database_url)
    processed = process_once(session_factory, worker_name="worker-announcement")

    assert processed is True

    db_session.expire_all()
    runs = db_session.execute(
        select(AnnouncementRun).where(AnnouncementRun.source_id == source.source_id)
    ).scalars()
    assert len(list(runs)) == 1
