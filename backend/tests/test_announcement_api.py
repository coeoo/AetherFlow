import uuid

from app.models import (
    AnnouncementDocument,
    AnnouncementIntelligencePackage,
    AnnouncementRun,
    AnnouncementSource,
    DeliveryRecord,
    DeliveryTarget,
    TaskJob,
)


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
        status="prepared",
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
            "status": "prepared",
            "error_message": None,
            "created_at": record.created_at.isoformat(),
            "payload_summary": {"title": "OpenSSL advisory"},
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
            "status": "prepared",
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
        status="prepared",
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
            "status": "prepared",
            "error_message": None,
            "created_at": record.created_at.isoformat(),
            "payload_summary": {"title": "OpenSSL advisory"},
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
        status="prepared",
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

    response = client.get("/api/v1/platform/delivery-records?scene_name=announcement&status=prepared")

    assert response.status_code == 200
    body = response.json()
    assert body["code"] == 0
    assert [item["status"] for item in body["data"]] == ["prepared"]
    assert [item["payload_summary"]["title"] for item in body["data"]] == ["OpenSSL advisory"]


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
            "config_summary": {
                "webhook_url": "https://example.com/webhook",
                "scene_names": ["announcement"],
            },
        },
        {
            "target_id": str(disabled_target.target_id),
            "name": "Webhook 备用通道",
            "channel_type": "webhook",
            "enabled": False,
            "config_summary": {
                "url": "https://example.com/fallback",
            },
        },
    ]


def test_patch_platform_delivery_target_updates_enabled_status(client, db_session) -> None:
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
        json={"enabled": False},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["code"] == 0
    assert body["data"] == {
        "target_id": str(target.target_id),
        "name": "安全响应群",
        "channel_type": "wecom",
        "enabled": False,
        "config_summary": {"scene_names": ["announcement"]},
    }

    db_session.expire_all()
    reloaded_target = db_session.get(DeliveryTarget, target.target_id)
    assert reloaded_target is not None
    assert reloaded_target.enabled is False
