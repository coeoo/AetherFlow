import uuid
from datetime import UTC, datetime, timedelta

import httpx

from app.models import (
    AnnouncementDocument,
    AnnouncementIntelligencePackage,
    AnnouncementRun,
    AnnouncementSource,
    DeliveryRecord,
    DeliveryTarget,
    SourceFetchRecord,
    TaskJob,
)
from app.config import load_settings
from app.scheduler.runtime import run_scheduler_once


def test_post_announcement_runs_creates_manual_url_run_and_task_job(
    client, db_session
) -> None:
    response = client.post(
        "/api/v1/announcements/runs",
        json={
            "input_mode": "url",
            "source_url": "https://example.com/advisory",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["code"] == 0
    assert body["message"] == "success"
    assert body["data"]["entry_mode"] == "manual_url"
    assert body["data"]["status"] == "queued"
    assert body["data"]["stage"] == "fetch_source"
    assert body["data"]["input_snapshot"]["source_url"] == "https://example.com/advisory"

    run_id = uuid.UUID(body["data"]["run_id"])
    run = db_session.get(AnnouncementRun, run_id)
    assert run is not None
    assert run.entry_mode == "manual_url"
    assert run.status == "queued"
    assert run.stage == "fetch_source"

    job = db_session.get(TaskJob, run.job_id)
    assert job is not None
    assert job.scene_name == "announcement"
    assert job.job_type == "announcement_manual_extract"
    assert job.trigger_kind == "manual"
    assert job.status == "queued"


def test_get_announcement_run_returns_detail_payload(client, db_session) -> None:
    job = TaskJob(
        scene_name="announcement",
        job_type="announcement_manual_extract",
        trigger_kind="manual",
        status="queued",
        payload_json={"source_url": "https://example.com/advisory"},
    )
    db_session.add(job)
    db_session.flush()

    run = AnnouncementRun(
        job_id=job.job_id,
        entry_mode="manual_url",
        status="queued",
        stage="fetch_source",
        input_snapshot_json={"source_url": "https://example.com/advisory"},
        summary_json={},
    )
    db_session.add(run)
    db_session.commit()
    db_session.refresh(run)

    response = client.get(f"/api/v1/announcements/runs/{run.run_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["code"] == 0
    assert body["message"] == "success"
    assert body["data"]["run_id"] == str(run.run_id)
    assert body["data"]["entry_mode"] == "manual_url"
    assert body["data"]["status"] == "queued"
    assert body["data"]["stage"] == "fetch_source"
    assert body["data"]["summary"] == {}
    assert body["data"]["document"] is None
    assert body["data"]["package"] is None
    assert body["data"]["delivery"] == {
        "run_id": str(run.run_id),
        "notify_recommended": False,
        "auto_send_applied": False,
        "skip_reason": "当前运行尚未生成可投递结果",
        "matched_targets": [],
        "recent_records": [],
    }


def test_get_announcement_run_returns_404_for_missing_run(client) -> None:
    response = client.get(f"/api/v1/announcements/runs/{uuid.uuid4()}")

    assert response.status_code == 404


def test_get_announcement_sources_returns_configured_sources(client, db_session) -> None:
    source = AnnouncementSource(
        name="Openwall OSS Security",
        source_type="openwall",
        enabled=True,
        schedule_cron="0 */2 * * *",
        config_json={"days_back": 3, "max_documents": 5},
        delivery_policy_json={},
    )
    db_session.add(source)
    db_session.commit()

    response = client.get("/api/v1/announcements/sources")

    assert response.status_code == 200
    body = response.json()
    assert body["code"] == 0
    assert body["data"] == [
        {
            "source_id": str(source.source_id),
            "name": "Openwall OSS Security",
            "source_type": "openwall",
            "enabled": True,
            "schedule_cron": "0 */2 * * *",
            "config": {"days_back": 3, "max_documents": 5},
            "delivery_policy": {},
        }
    ]


def test_post_run_now_creates_monitor_job_for_source(client, db_session) -> None:
    source = AnnouncementSource(
        name="Openwall OSS Security",
        source_type="openwall",
        enabled=True,
        schedule_cron="0 */2 * * *",
        config_json={"days_back": 3, "max_documents": 5},
        delivery_policy_json={},
    )
    db_session.add(source)
    db_session.commit()

    response = client.post(f"/api/v1/announcements/sources/{source.source_id}/run-now")

    assert response.status_code == 200
    body = response.json()
    assert body["code"] == 0
    assert body["data"]["source_id"] == str(source.source_id)
    assert body["data"]["job_type"] == "announcement_monitor_fetch"
    assert body["data"]["status"] == "queued"

    job = db_session.get(TaskJob, uuid.UUID(body["data"]["job_id"]))
    assert job is not None
    assert job.scene_name == "announcement"
    assert job.job_type == "announcement_monitor_fetch"
    assert job.trigger_kind == "manual"
    assert job.payload_json["source_id"] == str(source.source_id)


def test_get_monitor_runs_returns_batch_summaries(client, db_session) -> None:
    source = AnnouncementSource(
        name="Openwall OSS Security",
        source_type="openwall",
        enabled=True,
        schedule_cron="0 */2 * * *",
        config_json={"days_back": 3, "max_documents": 5},
        delivery_policy_json={},
    )
    db_session.add(source)
    db_session.flush()

    fetch_record = SourceFetchRecord(
        scene_name="announcement",
        source_id=source.source_id,
        source_type="announcement_monitor_fetch",
        source_ref=source.name,
        status="succeeded",
        request_snapshot_json={
            "source_id": str(source.source_id),
            "source_type": source.source_type,
        },
        response_meta_json={
            "discovered_count": 3,
            "new_count": 2,
        },
    )
    db_session.add(fetch_record)
    db_session.flush()

    for index in range(2):
        job = TaskJob(
            scene_name="announcement",
            job_type="announcement_manual_extract",
            trigger_kind="monitor",
            status="queued",
            payload_json={"source_url": f"https://example.com/advisory-{index}"},
        )
        db_session.add(job)
        db_session.flush()
        run = AnnouncementRun(
            job_id=job.job_id,
            entry_mode="monitor_source",
            source_id=source.source_id,
            trigger_fetch_id=fetch_record.fetch_id,
            status="queued",
            stage="fetch_source",
            title_hint=f"OpenSSL advisory {index}",
            input_snapshot_json={"source_url": f"https://example.com/advisory-{index}"},
            summary_json={},
        )
        db_session.add(run)

    db_session.commit()

    response = client.get("/api/v1/announcements/monitor-runs")

    assert response.status_code == 200
    body = response.json()
    assert body["code"] == 0
    assert body["data"] == [
        {
            "fetch_id": str(fetch_record.fetch_id),
            "source_id": str(source.source_id),
            "source_name": "Openwall OSS Security",
            "source_type": "openwall",
            "status": "succeeded",
            "discovered_count": 3,
            "new_count": 2,
            "extraction_run_count": 2,
            "created_at": fetch_record.created_at.isoformat(),
        }
    ]


def test_get_monitor_run_detail_returns_batch_and_triggered_runs(client, db_session) -> None:
    source = AnnouncementSource(
        name="Openwall OSS Security",
        source_type="openwall",
        enabled=True,
        schedule_cron="0 */2 * * *",
        config_json={"days_back": 3, "max_documents": 5},
        delivery_policy_json={},
    )
    db_session.add(source)
    db_session.flush()

    fetch_record = SourceFetchRecord(
        scene_name="announcement",
        source_id=source.source_id,
        source_type="announcement_monitor_fetch",
        source_ref=source.name,
        status="failed",
        request_snapshot_json={
            "source_id": str(source.source_id),
            "source_type": source.source_type,
        },
        response_meta_json={
            "discovered_count": 2,
            "new_count": 1,
        },
        error_message="上游源响应超时",
    )
    db_session.add(fetch_record)
    db_session.flush()

    job = TaskJob(
        scene_name="announcement",
        job_type="announcement_manual_extract",
        trigger_kind="monitor",
        status="succeeded",
        payload_json={"source_url": "https://example.com/advisory"},
    )
    db_session.add(job)
    db_session.flush()

    run = AnnouncementRun(
        job_id=job.job_id,
        entry_mode="monitor_source",
        source_id=source.source_id,
        trigger_fetch_id=fetch_record.fetch_id,
        status="succeeded",
        stage="finalize_run",
        title_hint="OpenSSL advisory",
        input_snapshot_json={
            "source_url": "https://example.com/advisory",
            "source_name": "Openwall",
        },
        summary_json={
            "linux_related": True,
            "confidence": 0.9,
        },
    )
    db_session.add(run)
    db_session.commit()

    response = client.get(f"/api/v1/announcements/monitor-runs/{fetch_record.fetch_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["code"] == 0
    assert body["data"] == {
        "fetch_id": str(fetch_record.fetch_id),
        "source_id": str(source.source_id),
        "source_name": "Openwall OSS Security",
        "source_type": "openwall",
        "status": "failed",
        "discovered_count": 2,
        "new_count": 1,
        "extraction_run_count": 1,
        "created_at": fetch_record.created_at.isoformat(),
        "error_message": "上游源响应超时",
        "request_snapshot": {
            "source_id": str(source.source_id),
            "source_type": "openwall",
        },
        "triggered_runs": [
            {
                "run_id": str(run.run_id),
                "entry_mode": "monitor_source",
                "status": "succeeded",
                "stage": "finalize_run",
                "title_hint": "OpenSSL advisory",
                "source_url": "https://example.com/advisory",
                "summary": {
                    "linux_related": True,
                    "confidence": 0.9,
                },
                "created_at": run.created_at.isoformat(),
            }
        ],
    }


def test_get_monitor_run_detail_returns_404_for_missing_batch(client) -> None:
    response = client.get(f"/api/v1/announcements/monitor-runs/{uuid.uuid4()}")

    assert response.status_code == 404


def test_get_announcement_run_returns_delivery_panel_with_matched_targets_and_records(
    client, db_session
) -> None:
    target = DeliveryTarget(
        name="安全响应群",
        channel_type="wecom",
        enabled=True,
        config_json={},
    )
    other_target = DeliveryTarget(
        name="已禁用群",
        channel_type="wecom",
        enabled=False,
        config_json={},
    )
    db_session.add_all([target, other_target])
    db_session.flush()

    source = AnnouncementSource(
        name="Openwall OSS Security",
        source_type="openwall",
        enabled=True,
        schedule_cron="0 */2 * * *",
        config_json={"days_back": 3, "max_documents": 5},
        delivery_policy_json={"target_ids": [str(target.target_id)]},
    )
    db_session.add(source)
    db_session.flush()

    job = TaskJob(
        scene_name="announcement",
        job_type="announcement_manual_extract",
        trigger_kind="manual",
        status="succeeded",
        payload_json={"source_url": "https://example.com/advisory"},
    )
    db_session.add(job)
    db_session.flush()

    run = AnnouncementRun(
        job_id=job.job_id,
        entry_mode="monitor_source",
        source_id=source.source_id,
        status="succeeded",
        stage="finalize_run",
        input_snapshot_json={"source_url": "https://example.com/advisory"},
        summary_json={"notify_recommended": True},
    )
    db_session.add(run)
    db_session.flush()

    document = AnnouncementDocument(
        run_id=run.run_id,
        source_id=source.source_id,
        title="OpenSSL advisory",
        source_name="Openwall",
        source_url="https://example.com/advisory",
        content_dedup_hash="a" * 64,
    )
    db_session.add(document)
    db_session.flush()

    package = AnnouncementIntelligencePackage(
        run_id=run.run_id,
        document_id=document.document_id,
        confidence=0.9,
        severity="high",
        affected_products_json=[],
        iocs_json=[],
        remediation_json=[],
        evidence_json=[],
        analyst_summary="检测到与 Linux 生态相关的安全公告。",
        notify_recommended=True,
    )
    db_session.add(package)
    db_session.flush()

    record = DeliveryRecord(
        target_id=target.target_id,
        scene_name="announcement",
        source_ref_type="announcement_run",
        source_ref_id=run.run_id,
        status="queued",
        delivery_kind="production",
        payload_summary_json={"title": "OpenSSL advisory"},
        response_snapshot_json={"mode": "platform_only"},
    )
    db_session.add(record)
    db_session.commit()

    response = client.get(f"/api/v1/announcements/runs/{run.run_id}")

    assert response.status_code == 200
    body = response.json()
    delivery = body["data"]["delivery"]
    assert delivery["notify_recommended"] is True
    assert delivery["auto_send_applied"] is False
    assert delivery["skip_reason"] is None
    assert delivery["matched_targets"] == [
        {
            "target_id": str(target.target_id),
            "name": "安全响应群",
            "channel_type": "wecom",
            "match_reason": "命中来源投递白名单",
        }
    ]
    assert delivery["recent_records"] == [
        {
            "record_id": str(record.record_id),
            "scene_name": "announcement",
            "source_ref_type": "announcement_run",
            "source_ref_id": str(run.run_id),
            "target_id": str(target.target_id),
            "target_name": "安全响应群",
            "channel_type": "wecom",
            "delivery_kind": "production",
            "status": "queued",
            "error_message": None,
            "scheduled_at": None,
            "sent_at": None,
            "created_at": record.created_at.isoformat(),
            "payload_summary": {"title": "OpenSSL advisory"},
            "response_snapshot": {"mode": "platform_only"},
        }
    ]


def test_post_announcement_run_deliveries_creates_prepared_records_for_matched_targets(
    client, db_session
) -> None:
    target = DeliveryTarget(
        name="安全响应群",
        channel_type="wecom",
        enabled=True,
        config_json={},
    )
    db_session.add(target)
    db_session.flush()

    source = AnnouncementSource(
        name="Openwall OSS Security",
        source_type="openwall",
        enabled=True,
        schedule_cron="0 */2 * * *",
        config_json={"days_back": 3, "max_documents": 5},
        delivery_policy_json={"target_ids": [str(target.target_id)]},
    )
    db_session.add(source)
    db_session.flush()

    job = TaskJob(
        scene_name="announcement",
        job_type="announcement_manual_extract",
        trigger_kind="manual",
        status="succeeded",
        payload_json={"source_url": "https://example.com/advisory"},
    )
    db_session.add(job)
    db_session.flush()

    run = AnnouncementRun(
        job_id=job.job_id,
        entry_mode="monitor_source",
        source_id=source.source_id,
        status="succeeded",
        stage="finalize_run",
        input_snapshot_json={"source_url": "https://example.com/advisory"},
        summary_json={"notify_recommended": True},
    )
    db_session.add(run)
    db_session.flush()

    document = AnnouncementDocument(
        run_id=run.run_id,
        source_id=source.source_id,
        title="OpenSSL advisory",
        source_name="Openwall",
        source_url="https://example.com/advisory",
        content_dedup_hash="b" * 64,
    )
    db_session.add(document)
    db_session.flush()

    package = AnnouncementIntelligencePackage(
        run_id=run.run_id,
        document_id=document.document_id,
        confidence=0.9,
        severity="high",
        affected_products_json=[],
        iocs_json=[],
        remediation_json=[],
        evidence_json=[],
        analyst_summary="检测到与 Linux 生态相关的安全公告。",
        notify_recommended=True,
    )
    db_session.add(package)
    db_session.commit()

    response = client.post(f"/api/v1/announcements/runs/{run.run_id}/deliveries", json={})

    assert response.status_code == 200
    body = response.json()
    assert body["code"] == 0
    assert body["data"]["run_id"] == str(run.run_id)
    assert body["data"]["created_count"] == 1
    assert body["data"]["records"] == [
        {
            "target_id": str(target.target_id),
            "target_name": "安全响应群",
            "record_id": body["data"]["records"][0]["record_id"],
            "delivery_kind": "production",
            "status": "queued",
            "scheduled_at": None,
        }
    ]

    records = (
        db_session.query(DeliveryRecord)
        .filter(
            DeliveryRecord.scene_name == "announcement",
            DeliveryRecord.source_ref_type == "announcement_run",
            DeliveryRecord.source_ref_id == run.run_id,
        )
        .all()
    )
    assert len(records) == 1
    assert records[0].status == "queued"
    assert records[0].delivery_kind == "production"
    assert records[0].payload_summary_json["title"] == "OpenSSL advisory"

    second_response = client.post(f"/api/v1/announcements/runs/{run.run_id}/deliveries", json={})
    assert second_response.status_code == 200
    assert second_response.json()["data"]["created_count"] == 0


def test_get_platform_delivery_records_returns_announcement_records(client, db_session) -> None:
    target = DeliveryTarget(
        name="安全响应群",
        channel_type="wecom",
        enabled=True,
        config_json={},
    )
    db_session.add(target)
    db_session.flush()

    record = DeliveryRecord(
        target_id=target.target_id,
        scene_name="announcement",
        source_ref_type="announcement_run",
        source_ref_id=uuid.uuid4(),
        status="queued",
        delivery_kind="production",
        payload_summary_json={"title": "OpenSSL advisory"},
        response_snapshot_json={"mode": "platform_only"},
    )
    db_session.add(record)
    db_session.commit()

    response = client.get("/api/v1/platform/delivery-records?scene_name=announcement")

    assert response.status_code == 200
    body = response.json()
    assert body["code"] == 0
    assert body["data"] == [
        {
            "record_id": str(record.record_id),
            "scene_name": "announcement",
            "source_ref_type": "announcement_run",
            "source_ref_id": str(record.source_ref_id),
            "target_id": str(target.target_id),
            "target_name": "安全响应群",
            "channel_type": "wecom",
            "delivery_kind": "production",
            "status": "queued",
            "error_message": None,
            "scheduled_at": None,
            "sent_at": None,
            "created_at": record.created_at.isoformat(),
            "payload_summary": {"title": "OpenSSL advisory"},
            "response_snapshot": {},
        }
    ]


def test_get_platform_delivery_records_filters_by_status(client, db_session) -> None:
    target = DeliveryTarget(
        name="安全响应群",
        channel_type="wecom",
        enabled=True,
        config_json={},
    )
    db_session.add(target)
    db_session.flush()

    prepared_record = DeliveryRecord(
        target_id=target.target_id,
        scene_name="announcement",
        source_ref_type="announcement_run",
        source_ref_id=uuid.uuid4(),
        status="queued",
        delivery_kind="production",
        payload_summary_json={"title": "OpenSSL advisory"},
        response_snapshot_json={"mode": "platform_only"},
    )
    skipped_record = DeliveryRecord(
        target_id=target.target_id,
        scene_name="announcement",
        source_ref_type="announcement_run",
        source_ref_id=uuid.uuid4(),
        status="skipped",
        payload_summary_json={"title": "Kernel advisory"},
        response_snapshot_json={"mode": "platform_only"},
    )
    db_session.add_all([prepared_record, skipped_record])
    db_session.commit()

    response = client.get("/api/v1/platform/delivery-records?scene_name=announcement&status=queued")

    assert response.status_code == 200
    body = response.json()
    assert body["code"] == 0
    assert [item["status"] for item in body["data"]] == ["queued"]
    assert [item["payload_summary"]["title"] for item in body["data"]] == ["OpenSSL advisory"]


def test_get_platform_delivery_records_filters_by_channel_type(client, db_session) -> None:
    wecom_target = DeliveryTarget(
        name="安全响应群",
        channel_type="wecom",
        enabled=True,
        config_json={},
    )
    email_target = DeliveryTarget(
        name="邮件通知组",
        channel_type="email",
        enabled=True,
        config_json={},
    )
    db_session.add_all([wecom_target, email_target])
    db_session.flush()

    wecom_record = DeliveryRecord(
        target_id=wecom_target.target_id,
        scene_name="announcement",
        source_ref_type="announcement_run",
        source_ref_id=uuid.uuid4(),
        status="queued",
        delivery_kind="production",
        payload_summary_json={"title": "OpenSSL advisory"},
        response_snapshot_json={"mode": "platform_only"},
    )
    email_record = DeliveryRecord(
        target_id=email_target.target_id,
        scene_name="announcement",
        source_ref_type="announcement_run",
        source_ref_id=uuid.uuid4(),
        status="queued",
        delivery_kind="production",
        payload_summary_json={"title": "Kernel advisory"},
        response_snapshot_json={"mode": "platform_only"},
    )
    db_session.add_all([wecom_record, email_record])
    db_session.commit()

    response = client.get(
        "/api/v1/platform/delivery-records?scene_name=announcement&channel_type=email"
    )

    assert response.status_code == 200
    body = response.json()
    assert body["code"] == 0
    assert [item["channel_type"] for item in body["data"]] == ["email"]
    assert [item["payload_summary"]["title"] for item in body["data"]] == ["Kernel advisory"]


def test_get_platform_delivery_records_filters_by_delivery_kind(client, db_session) -> None:
    target = DeliveryTarget(
        name="安全响应群",
        channel_type="wecom",
        enabled=True,
        config_json={"webhook_url": "https://example.com/wecom"},
    )
    db_session.add(target)
    db_session.flush()

    production_record = DeliveryRecord(
        target_id=target.target_id,
        scene_name="announcement",
        source_ref_type="announcement_run",
        source_ref_id=uuid.uuid4(),
        status="queued",
        delivery_kind="production",
        payload_summary_json={"title": "OpenSSL advisory"},
        response_snapshot_json={"mode": "platform_only"},
    )
    test_record = DeliveryRecord(
        target_id=target.target_id,
        scene_name="platform",
        source_ref_type="delivery_target",
        source_ref_id=target.target_id,
        status="failed",
        delivery_kind="test",
        payload_summary_json={"title": "平台测试发送"},
        response_snapshot_json={"mode": "test"},
    )
    db_session.add_all([production_record, test_record])
    db_session.commit()

    response = client.get("/api/v1/platform/delivery-records?delivery_kind=test")

    assert response.status_code == 200
    body = response.json()
    assert [item["delivery_kind"] for item in body["data"]] == ["test"]
    assert [item["payload_summary"]["title"] for item in body["data"]] == ["平台测试发送"]


def test_get_platform_delivery_targets_returns_target_views(client, db_session) -> None:
    enabled_target = DeliveryTarget(
        name="安全响应群",
        channel_type="wecom",
        enabled=True,
        config_json={"webhook_url": "https://example.com/webhook", "scene_names": ["announcement"]},
    )
    disabled_target = DeliveryTarget(
        name="Webhook 备用通道",
        channel_type="webhook",
        enabled=False,
        config_json={"url": "https://example.com/fallback"},
    )
    db_session.add_all([enabled_target, disabled_target])
    db_session.commit()

    response = client.get("/api/v1/platform/delivery-targets")

    assert response.status_code == 200
    body = response.json()
    assert body["code"] == 0
    assert body["data"] == [
        {
            "target_id": str(enabled_target.target_id),
            "name": "安全响应群",
            "channel_type": "wecom",
            "enabled": True,
            "config_json": {
                "webhook_url": "<已隐藏: https://example.com>",
                "scene_names": ["announcement"],
            },
            "config_summary": {
                "webhook_url": "<已隐藏: https://example.com>",
                "scene_names": ["announcement"],
            },
        },
        {
            "target_id": str(disabled_target.target_id),
            "name": "Webhook 备用通道",
            "channel_type": "webhook",
            "enabled": False,
            "config_json": {
                "url": "<已隐藏: https://example.com>",
            },
            "config_summary": {
                "url": "<已隐藏: https://example.com>",
            },
        },
    ]


def test_post_platform_delivery_target_creates_target(client, db_session) -> None:
    response = client.post(
        "/api/v1/platform/delivery-targets",
        json={
            "name": "邮件通知组",
            "channel_type": "email",
            "enabled": True,
            "config_json": {
                "recipients": ["soc@example.com"],
                "scene_names": ["announcement"],
            },
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["code"] == 0
    assert body["data"]["name"] == "邮件通知组"
    assert body["data"]["channel_type"] == "email"
    assert body["data"]["enabled"] is True
    assert body["data"]["config_json"] == {
        "recipients": ["soc@example.com"],
        "scene_names": ["announcement"],
    }

    created_target = (
        db_session.query(DeliveryTarget)
        .filter(DeliveryTarget.name == "邮件通知组")
        .one_or_none()
    )
    assert created_target is not None
    assert created_target.channel_type == "email"
    assert created_target.enabled is True
    assert created_target.config_json == {
        "recipients": ["soc@example.com"],
        "scene_names": ["announcement"],
    }


def test_patch_platform_delivery_target_updates_editable_fields(client, db_session) -> None:
    target = DeliveryTarget(
        name="安全响应群",
        channel_type="wecom",
        enabled=True,
        config_json={"scene_names": ["announcement"]},
    )
    db_session.add(target)
    db_session.commit()

    response = client.patch(
        f"/api/v1/platform/delivery-targets/{target.target_id}",
        json={
            "name": "公告邮件组",
            "channel_type": "email",
            "enabled": False,
            "config_json": {
                "recipients": ["team@example.com"],
                "scene_names": ["announcement"],
            },
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["code"] == 0
    assert body["data"] == {
        "target_id": str(target.target_id),
        "name": "公告邮件组",
        "channel_type": "email",
        "enabled": False,
        "config_json": {
            "recipients": ["team@example.com"],
            "scene_names": ["announcement"],
        },
        "config_summary": {
            "recipients": ["team@example.com"],
            "scene_names": ["announcement"],
        },
    }

    db_session.expire_all()
    reloaded_target = db_session.get(DeliveryTarget, target.target_id)
    assert reloaded_target is not None
    assert reloaded_target.name == "公告邮件组"
    assert reloaded_target.channel_type == "email"
    assert reloaded_target.enabled is False
    assert reloaded_target.config_json == {
        "recipients": ["team@example.com"],
        "scene_names": ["announcement"],
    }


def test_patch_platform_delivery_target_keeps_existing_secret_when_payload_uses_masked_value(
    client, db_session
) -> None:
    target = DeliveryTarget(
        name="Webhook 通知组",
        channel_type="webhook",
        enabled=True,
        config_json={
            "url": "https://example.com/hooks/aetherflow-secret",
            "scene_names": ["announcement"],
        },
    )
    db_session.add(target)
    db_session.commit()

    response = client.patch(
        f"/api/v1/platform/delivery-targets/{target.target_id}",
        json={
            "name": "Webhook 通知组（已更新）",
            "config_json": {
                "url": "<已隐藏: https://example.com>",
                "scene_names": ["announcement", "platform"],
            },
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["code"] == 0
    assert body["data"] == {
        "target_id": str(target.target_id),
        "name": "Webhook 通知组（已更新）",
        "channel_type": "webhook",
        "enabled": True,
        "config_json": {
            "url": "<已隐藏: https://example.com>",
            "scene_names": ["announcement", "platform"],
        },
        "config_summary": {
            "url": "<已隐藏: https://example.com>",
            "scene_names": ["announcement", "platform"],
        },
    }

    db_session.expire_all()
    reloaded_target = db_session.get(DeliveryTarget, target.target_id)
    assert reloaded_target is not None
    assert reloaded_target.name == "Webhook 通知组（已更新）"
    assert reloaded_target.config_json == {
        "url": "https://example.com/hooks/aetherflow-secret",
        "scene_names": ["announcement", "platform"],
    }


def test_post_platform_delivery_target_test_creates_sent_test_record(
    client, db_session, monkeypatch
) -> None:
    target = DeliveryTarget(
        name="Webhook 通知组",
        channel_type="webhook",
        enabled=True,
        config_json={"url": "https://example.com/hooks/aetherflow"},
    )
    db_session.add(target)
    db_session.commit()

    def _fake_http_post(url: str, **kwargs) -> httpx.Response:
        request = httpx.Request("POST", url)
        assert kwargs["json"]["delivery_kind"] == "test"
        assert kwargs["json"]["title"] == "平台测试发送"
        return httpx.Response(200, json={"ok": True}, request=request)

    monkeypatch.setattr("httpx.post", _fake_http_post)

    response = client.post(f"/api/v1/platform/delivery-targets/{target.target_id}/test", json={})

    assert response.status_code == 200
    body = response.json()
    assert body["data"]["target_id"] == str(target.target_id)
    assert body["data"]["delivery_kind"] == "test"
    assert body["data"]["status"] == "sent"
    assert body["data"]["sent_at"] is not None

    db_session.expire_all()
    records = (
        db_session.query(DeliveryRecord)
        .filter(DeliveryRecord.target_id == target.target_id)
        .order_by(DeliveryRecord.created_at.desc())
        .all()
    )
    assert len(records) == 1
    assert records[0].delivery_kind == "test"
    assert records[0].status == "sent"
    assert body["data"]["response_snapshot"] == {
        "channel_type": "webhook",
        "status_code": 200,
        "target_summary": "https://example.com",
    }


def test_post_platform_delivery_target_test_rejects_disabled_target(client, db_session) -> None:
    target = DeliveryTarget(
        name="禁用 Webhook 通知组",
        channel_type="webhook",
        enabled=False,
        config_json={"url": "https://example.com/hooks/aetherflow"},
    )
    db_session.add(target)
    db_session.commit()

    response = client.post(f"/api/v1/platform/delivery-targets/{target.target_id}/test", json={})

    assert response.status_code == 400
    assert response.json()["detail"] == "禁用目标不允许测试发送"


def test_post_platform_delivery_target_rejects_insecure_or_private_url(client) -> None:
    insecure_response = client.post(
        "/api/v1/platform/delivery-targets",
        json={
            "name": "不安全 Webhook",
            "channel_type": "webhook",
            "enabled": True,
            "config_json": {
                "url": "http://127.0.0.1/internal",
            },
        },
    )

    assert insecure_response.status_code == 400
    assert insecure_response.json()["detail"] == "投递目标地址必须使用 https"

    private_response = client.post(
        "/api/v1/platform/delivery-targets",
        json={
            "name": "内网 Webhook",
            "channel_type": "webhook",
            "enabled": True,
            "config_json": {
                "url": "https://127.0.0.1/internal",
            },
        },
    )

    assert private_response.status_code == 400
    assert private_response.json()["detail"] == "投递目标地址不允许指向本机、内网或保留地址"


def test_post_platform_delivery_record_send_executes_queued_record(
    client, db_session, monkeypatch
) -> None:
    target = DeliveryTarget(
        name="Webhook 通知组",
        channel_type="webhook",
        enabled=True,
        config_json={"url": "https://example.com/hooks/aetherflow"},
    )
    db_session.add(target)
    db_session.flush()

    record = DeliveryRecord(
        target_id=target.target_id,
        scene_name="announcement",
        source_ref_type="announcement_run",
        source_ref_id=uuid.uuid4(),
        status="queued",
        delivery_kind="production",
        payload_summary_json={"title": "OpenSSL advisory"},
        response_snapshot_json={"mode": "platform_only"},
    )
    db_session.add(record)
    db_session.commit()

    def _fake_http_post(url: str, **kwargs) -> httpx.Response:
        request = httpx.Request("POST", url)
        assert kwargs["json"]["delivery_kind"] == "production"
        assert kwargs["json"]["title"] == "OpenSSL advisory"
        return httpx.Response(200, json={"delivered": True}, request=request)

    monkeypatch.setattr("httpx.post", _fake_http_post)

    response = client.post(f"/api/v1/platform/delivery-records/{record.record_id}/send")

    assert response.status_code == 200
    body = response.json()
    assert body["data"]["record_id"] == str(record.record_id)
    assert body["data"]["status"] == "sent"
    assert body["data"]["delivery_kind"] == "production"
    assert body["data"]["sent_at"] is not None
    assert body["data"]["response_snapshot"] == {
        "channel_type": "webhook",
        "status_code": 200,
        "target_summary": "https://example.com",
    }

    db_session.expire_all()
    reloaded_record = db_session.get(DeliveryRecord, record.record_id)
    assert reloaded_record is not None
    assert reloaded_record.status == "sent"
    assert reloaded_record.sent_at is not None


def test_post_platform_delivery_record_retry_retries_failed_record(
    client, db_session, monkeypatch
) -> None:
    target = DeliveryTarget(
        name="Webhook 通知组",
        channel_type="webhook",
        enabled=True,
        config_json={"url": "https://example.com/hooks/aetherflow"},
    )
    db_session.add(target)
    db_session.flush()

    record = DeliveryRecord(
        target_id=target.target_id,
        scene_name="announcement",
        source_ref_type="announcement_run",
        source_ref_id=uuid.uuid4(),
        status="failed",
        delivery_kind="production",
        payload_summary_json={"title": "OpenSSL advisory"},
        response_snapshot_json={"status_code": 500},
        error_message="首次发送失败",
    )
    db_session.add(record)
    db_session.commit()

    def _fake_http_post(url: str, **kwargs) -> httpx.Response:
        request = httpx.Request("POST", url)
        return httpx.Response(200, json={"delivered": True}, request=request)

    monkeypatch.setattr("httpx.post", _fake_http_post)

    response = client.post(f"/api/v1/platform/delivery-records/{record.record_id}/retry")

    assert response.status_code == 200
    body = response.json()
    assert body["data"]["status"] == "sent"
    assert body["data"]["error_message"] is None

    db_session.expire_all()
    reloaded_record = db_session.get(DeliveryRecord, record.record_id)
    assert reloaded_record is not None
    assert reloaded_record.status == "sent"
    assert reloaded_record.error_message is None


def test_get_platform_delivery_records_sanitizes_legacy_target_summary(client, db_session) -> None:
    target = DeliveryTarget(
        name="Webhook 通知组",
        channel_type="webhook",
        enabled=True,
        config_json={"url": "https://example.com/hooks/aetherflow-secret"},
    )
    db_session.add(target)
    db_session.flush()

    record = DeliveryRecord(
        target_id=target.target_id,
        scene_name="announcement",
        source_ref_type="announcement_run",
        source_ref_id=uuid.uuid4(),
        status="sent",
        delivery_kind="production",
        payload_summary_json={"title": "OpenSSL advisory"},
        response_snapshot_json={
            "channel_type": "webhook",
            "status_code": 200,
            "target_summary": "https://example.com/hooks/aetherflow-secret",
            "delivery_url": "https://example.com/hooks/aetherflow-secret?token=abc",
            "response_body": {"ok": True},
        },
    )
    db_session.add(record)
    db_session.commit()

    response = client.get("/api/v1/platform/delivery-records?scene_name=announcement")

    assert response.status_code == 200
    body = response.json()
    assert body["code"] == 0
    assert body["data"][0]["response_snapshot"] == {
        "channel_type": "webhook",
        "status_code": 200,
        "target_summary": "https://example.com",
    }


def test_post_platform_delivery_record_schedule_sets_scheduled_at(client, db_session) -> None:
    target = DeliveryTarget(
        name="安全响应群",
        channel_type="wecom",
        enabled=True,
        config_json={"webhook_url": "https://example.com/wecom"},
    )
    db_session.add(target)
    db_session.flush()

    record = DeliveryRecord(
        target_id=target.target_id,
        scene_name="announcement",
        source_ref_type="announcement_run",
        source_ref_id=uuid.uuid4(),
        status="queued",
        delivery_kind="production",
        payload_summary_json={"title": "OpenSSL advisory"},
        response_snapshot_json={"mode": "platform_only"},
    )
    db_session.add(record)
    db_session.commit()

    scheduled_at = "2026-04-18T09:30:00+08:00"
    response = client.post(
        f"/api/v1/platform/delivery-records/{record.record_id}/schedule",
        json={"scheduled_at": scheduled_at},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["data"]["status"] == "queued"
    assert body["data"]["scheduled_at"] == "2026-04-18T01:30:00+00:00"

    db_session.expire_all()
    reloaded_record = db_session.get(DeliveryRecord, record.record_id)
    assert reloaded_record is not None
    assert reloaded_record.scheduled_at is not None
    assert reloaded_record.scheduled_at.isoformat() == "2026-04-18T01:30:00+00:00"


def test_scheduler_once_processes_due_delivery_records(
    db_session, test_database_url, monkeypatch
) -> None:
    target = DeliveryTarget(
        name="Webhook 通知组",
        channel_type="webhook",
        enabled=True,
        config_json={"url": "https://example.com/hooks/aetherflow"},
    )
    db_session.add(target)
    db_session.flush()

    record = DeliveryRecord(
        target_id=target.target_id,
        scene_name="announcement",
        source_ref_type="announcement_run",
        source_ref_id=uuid.uuid4(),
        status="queued",
        delivery_kind="production",
        scheduled_at=datetime.now(UTC) - timedelta(minutes=5),
        payload_summary_json={"title": "OpenSSL advisory"},
        response_snapshot_json={"mode": "platform_only"},
    )
    db_session.add(record)
    db_session.commit()

    def _fake_http_post(url: str, **kwargs) -> httpx.Response:
        request = httpx.Request("POST", url)
        return httpx.Response(200, json={"delivered": True}, request=request)

    monkeypatch.setattr("httpx.post", _fake_http_post)
    monkeypatch.setenv("DATABASE_URL", test_database_url)
    monkeypatch.delenv("AETHERFLOW_DATABASE_URL", raising=False)

    run_scheduler_once(load_settings(), instance_name="delivery-scheduler-test")

    db_session.expire_all()
    reloaded_record = db_session.get(DeliveryRecord, record.record_id)
    assert reloaded_record is not None
    assert reloaded_record.status == "sent"
    assert reloaded_record.sent_at is not None
