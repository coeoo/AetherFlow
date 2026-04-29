from __future__ import annotations

from datetime import datetime, timezone
import uuid

from app.models import (
    AnnouncementRun,
    CVERun,
    DeliveryRecord,
    DeliveryTarget,
    TaskAttempt,
    TaskJob,
)


def test_home_summary_aggregates_recent_jobs_deliveries_and_health(client, db_session) -> None:
    cve_job = TaskJob(
        job_id=uuid.uuid4(),
        scene_name="cve",
        job_type="cve_patch_agent_graph",
        trigger_kind="manual",
        status="running",
        payload_json={"cve_id": "CVE-2024-3094"},
    )
    announcement_job = TaskJob(
        job_id=uuid.uuid4(),
        scene_name="announcement",
        job_type="announcement_manual_extract",
        trigger_kind="manual",
        status="failed",
        payload_json={
            "input_mode": "url",
            "source_url": "https://example.com/advisory",
        },
        last_error="提取失败",
    )
    db_session.add_all([cve_job, announcement_job])
    db_session.flush()

    db_session.add(
        CVERun(
            job_id=cve_job.job_id,
            cve_id="CVE-2024-3094",
            status="running",
            phase="collect_patch_artifacts",
            summary_json={},
        )
    )
    db_session.add(
        AnnouncementRun(
            job_id=announcement_job.job_id,
            entry_mode="manual_url",
            status="failed",
            stage="extract_intelligence",
            input_snapshot_json={
                "input_mode": "url",
                "source_url": "https://example.com/advisory",
            },
            summary_json={"primary_title": "OpenSSL advisory"},
        )
    )

    target = DeliveryTarget(
        target_id=uuid.uuid4(),
        name="安全响应群",
        channel_type="wecom",
        enabled=True,
        config_json={"scene_names": ["announcement"]},
    )
    db_session.add(target)
    db_session.flush()

    db_session.add(
        DeliveryRecord(
            target_id=target.target_id,
            scene_name="announcement",
            source_ref_type="announcement_run",
            source_ref_id=uuid.uuid4(),
            status="prepared",
            payload_summary_json={
                "title": "OpenSSL advisory",
                "notify_recommended": True,
            },
            response_snapshot_json={},
        )
    )
    db_session.commit()

    response = client.get("/api/v1/platform/home-summary")

    assert response.status_code == 200
    body = response.json()
    assert body["code"] == 0
    assert body["data"]["platform_name"] == "AetherFlow"
    assert len(body["data"]["scenes"]) == 2
    cve_scene = next(scene for scene in body["data"]["scenes"] if scene["scene_name"] == "cve")
    assert cve_scene["path"] == "/patch"
    assert len(body["data"]["recent_jobs"]) == 2
    assert body["data"]["recent_jobs"][0]["scene_run_id"] is not None
    assert len(body["data"]["recent_deliveries"]) == 1
    assert body["data"]["recent_deliveries"][0]["target_name"] == "安全响应群"
    assert set(body["data"]["health"]) == {"api", "database", "worker", "scheduler", "notes"}


def test_platform_tasks_list_and_detail_include_scene_run_and_attempts(client, db_session) -> None:
    job = TaskJob(
        job_id=uuid.uuid4(),
        scene_name="cve",
        job_type="cve_patch_agent_graph",
        trigger_kind="manual",
        status="failed",
        payload_json={"cve_id": "CVE-2024-3094"},
        last_error="source fetch failed",
    )
    db_session.add(job)
    db_session.flush()

    run = CVERun(
        job_id=job.job_id,
        cve_id="CVE-2024-3094",
        status="failed",
        phase="fetch_sources",
        stop_reason="source_fetch_failed",
        summary_json={},
    )
    db_session.add(run)
    db_session.flush()

    first_attempt_started = datetime(2026, 4, 17, 2, 0, tzinfo=timezone.utc)
    second_attempt_started = datetime(2026, 4, 17, 2, 10, tzinfo=timezone.utc)
    db_session.add_all(
        [
            TaskAttempt(
                job_id=job.job_id,
                attempt_no=1,
                status="failed",
                worker_name="worker-a",
                error_message="network timeout",
                started_at=first_attempt_started,
                finished_at=first_attempt_started,
            ),
            TaskAttempt(
                job_id=job.job_id,
                attempt_no=2,
                status="failed",
                worker_name="worker-b",
                error_message="source fetch failed",
                started_at=second_attempt_started,
                finished_at=second_attempt_started,
            ),
        ]
    )
    db_session.commit()

    list_response = client.get("/api/v1/platform/tasks?status=failed")
    assert list_response.status_code == 200
    list_body = list_response.json()
    assert list_body["code"] == 0
    assert list_body["data"]["total"] == 1
    assert list_body["data"]["items"][0]["job_id"] == str(job.job_id)
    assert list_body["data"]["items"][0]["scene_run_id"] == str(run.run_id)
    assert list_body["data"]["items"][0]["last_attempt_at"] == second_attempt_started.isoformat()

    detail_response = client.get(f"/api/v1/platform/tasks/{job.job_id}")
    assert detail_response.status_code == 200
    detail_body = detail_response.json()
    assert detail_body["code"] == 0
    assert detail_body["data"]["job_id"] == str(job.job_id)
    assert detail_body["data"]["scene_run_id"] == str(run.run_id)
    assert detail_body["data"]["payload_summary"]["cve_id"] == "CVE-2024-3094"
    assert len(detail_body["data"]["attempts"]) == 2
    assert detail_body["data"]["attempts"][0]["attempt_no"] == 2
    assert detail_body["data"]["attempts"][0]["error_message"] == "source fetch failed"


def test_retry_failed_task_requeues_job(client, db_session) -> None:
    job = TaskJob(
        job_id=uuid.uuid4(),
        scene_name="announcement",
        job_type="announcement_manual_extract",
        trigger_kind="manual",
        status="failed",
        payload_json={
            "input_mode": "url",
            "source_url": "https://example.com/advisory",
        },
        last_error="extract failed",
    )
    db_session.add(job)
    db_session.flush()
    db_session.add(
        AnnouncementRun(
            job_id=job.job_id,
            entry_mode="manual_url",
            status="failed",
            stage="extract_intelligence",
            input_snapshot_json={
                "input_mode": "url",
                "source_url": "https://example.com/advisory",
            },
            summary_json={},
        )
    )
    db_session.add(
        TaskAttempt(
            job_id=job.job_id,
            attempt_no=1,
            status="failed",
            worker_name="worker-a",
            error_message="extract failed",
        )
    )
    db_session.commit()

    response = client.post(f"/api/v1/platform/tasks/{job.job_id}/retry")

    assert response.status_code == 200
    body = response.json()
    assert body["code"] == 0
    assert body["data"]["job_id"] == str(job.job_id)
    assert body["data"]["status"] == "queued"

    db_session.refresh(job)
    assert job.status == "queued"
    assert job.last_error is None
