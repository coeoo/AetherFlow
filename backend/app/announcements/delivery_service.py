from __future__ import annotations

from uuid import UUID

from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from app.models import (
    AnnouncementDocument,
    AnnouncementIntelligencePackage,
    AnnouncementRun,
    AnnouncementSource,
    DeliveryRecord,
    DeliveryTarget,
)

ALLOWED_DELIVERY_CHANNEL_TYPES = {"email", "wecom", "webhook"}


def get_announcement_delivery_panel(
    session: Session,
    *,
    run_id: UUID,
) -> dict[str, object] | None:
    run = session.get(AnnouncementRun, run_id)
    if run is None:
        return None

    document = _get_run_document(session, run_id=run.run_id)
    package = _get_run_package(session, run_id=run.run_id, document=document)
    source = session.get(AnnouncementSource, run.source_id) if run.source_id is not None else None

    notify_recommended = bool(package.notify_recommended) if package is not None else False
    matched_targets: list[dict[str, object]] = []
    skip_reason: str | None = None

    if package is None:
        skip_reason = "当前运行尚未生成可投递结果"
    elif not package.notify_recommended:
        skip_reason = "当前结果未建议投递"
    else:
        matched_targets = _match_delivery_targets(session, source=source)
        if not matched_targets:
            skip_reason = "当前没有匹配到启用的投递目标"

    return {
        "run_id": str(run.run_id),
        "notify_recommended": notify_recommended,
        "auto_send_applied": False,
        "skip_reason": skip_reason,
        "matched_targets": matched_targets,
        "recent_records": list_delivery_records_for_run(session, run_id=run.run_id, limit=3),
    }


def create_announcement_delivery_records(
    session: Session,
    *,
    run_id: UUID,
    target_ids: list[UUID] | None = None,
) -> dict[str, object]:
    panel = get_announcement_delivery_panel(session, run_id=run_id)
    if panel is None:
        raise LookupError("公告运行记录不存在")

    skip_reason = panel["skip_reason"]
    if skip_reason is not None and not panel["matched_targets"]:
        raise ValueError(str(skip_reason))

    run = session.get(AnnouncementRun, run_id)
    assert run is not None
    document = _get_run_document(session, run_id=run_id)
    package = _get_run_package(session, run_id=run_id, document=document)

    selectable_targets = list(panel["matched_targets"])
    if target_ids:
        allowed_target_ids = {str(target_id) for target_id in target_ids}
        selectable_targets = [
            target
            for target in selectable_targets
            if str(target["target_id"]) in allowed_target_ids
        ]

    if not selectable_targets:
        raise ValueError("当前没有可创建的投递目标")

    existing_records = session.execute(
        select(DeliveryRecord).where(
            DeliveryRecord.scene_name == "announcement",
            DeliveryRecord.source_ref_type == "announcement_run",
            DeliveryRecord.source_ref_id == run_id,
            DeliveryRecord.target_id.in_([UUID(str(target["target_id"])) for target in selectable_targets]),
        )
    ).scalars()
    existing_by_target_id = {
        str(record.target_id): record for record in existing_records if record.target_id is not None
    }

    created_count = 0
    serialized_records: list[dict[str, object]] = []
    for target in selectable_targets:
        existing_record = existing_by_target_id.get(str(target["target_id"]))
        if existing_record is not None:
            serialized_records.append(
                {
                    "target_id": str(target["target_id"]),
                    "target_name": target["name"],
                    "status": existing_record.status,
                }
            )
            continue

        record = DeliveryRecord(
            target_id=UUID(str(target["target_id"])),
            scene_name="announcement",
            source_ref_type="announcement_run",
            source_ref_id=run_id,
            status="prepared",
            payload_summary_json={
                "title": document.title if document is not None else (run.title_hint or "未命名安全公告"),
                "source_name": document.source_name if document is not None else None,
                "source_url": document.source_url if document is not None else None,
                "confidence": float(package.confidence) if package is not None else 0.0,
                "notify_recommended": bool(package.notify_recommended) if package is not None else False,
                "match_reason": target["match_reason"],
            },
            response_snapshot_json={
                "mode": "platform_only",
                "message": "Phase 3-A 仅生成平台内投递记录，未真实发送。",
            },
        )
        session.add(record)
        session.flush()
        created_count += 1
        serialized_records.append(
            {
                "target_id": str(target["target_id"]),
                "target_name": target["name"],
                "status": record.status,
            }
        )

    return {
        "run_id": str(run_id),
        "created_count": created_count,
        "records": serialized_records,
    }


def list_delivery_records_for_run(
    session: Session,
    *,
    run_id: UUID,
    limit: int,
) -> list[dict[str, object]]:
    rows = session.execute(
        _delivery_record_query().where(
            DeliveryRecord.scene_name == "announcement",
            DeliveryRecord.source_ref_type == "announcement_run",
            DeliveryRecord.source_ref_id == run_id,
        )
    ).all()

    records = [_serialize_delivery_record(record, target) for record, target in rows]
    records.sort(key=lambda item: str(item["created_at"]), reverse=True)
    return records[:limit]


def list_platform_delivery_records(
    session: Session,
    *,
    scene_name: str | None,
    status: str | None,
    channel_type: str | None,
    limit: int,
) -> list[dict[str, object]]:
    query = _delivery_record_query()
    if scene_name:
        query = query.where(DeliveryRecord.scene_name == scene_name)
    if status:
        query = query.where(DeliveryRecord.status == status)
    if channel_type:
        query = query.where(DeliveryTarget.channel_type == channel_type)

    rows = session.execute(query).all()
    records = [_serialize_delivery_record(record, target) for record, target in rows]
    records.sort(key=lambda item: str(item["created_at"]), reverse=True)
    return records[:limit]


def list_delivery_targets(session: Session) -> list[dict[str, object]]:
    targets = session.execute(select(DeliveryTarget)).scalars()
    serialized = [_serialize_delivery_target(target) for target in targets]
    serialized.sort(key=lambda item: (not bool(item["enabled"]), str(item["name"])))
    return serialized


def create_delivery_target(
    session: Session,
    *,
    name: str,
    channel_type: str,
    enabled: bool,
    config_json: dict[str, object] | None,
) -> dict[str, object]:
    validated_name = _normalize_delivery_target_name(name)
    validated_channel_type = _normalize_delivery_channel_type(channel_type)
    normalized_config = _normalize_delivery_target_config(config_json)

    target = DeliveryTarget(
        name=validated_name,
        channel_type=validated_channel_type,
        enabled=enabled,
        config_json=normalized_config,
    )
    session.add(target)
    session.flush()
    return _serialize_delivery_target(target)


def update_delivery_target(
    session: Session,
    *,
    target_id: UUID | str,
    name: str | None = None,
    channel_type: str | None = None,
    enabled: bool | None = None,
    config_json: dict[str, object] | None = None,
) -> dict[str, object]:
    target_uuid = UUID(str(target_id))
    target = session.get(DeliveryTarget, target_uuid)
    if target is None:
        raise LookupError("投递目标不存在")

    if name is not None:
        target.name = _normalize_delivery_target_name(name)
    if channel_type is not None:
        target.channel_type = _normalize_delivery_channel_type(channel_type)
    if enabled is not None:
        target.enabled = enabled
    if config_json is not None:
        target.config_json = _normalize_delivery_target_config(config_json)
    session.flush()

    return _serialize_delivery_target(target)


def _delivery_record_query() -> Select:
    return (
        select(DeliveryRecord, DeliveryTarget)
        .join(DeliveryTarget, DeliveryTarget.target_id == DeliveryRecord.target_id, isouter=True)
    )


def _get_run_document(session: Session, *, run_id: UUID) -> AnnouncementDocument | None:
    return session.execute(
        select(AnnouncementDocument).where(AnnouncementDocument.run_id == run_id)
    ).scalar_one_or_none()


def _get_run_package(
    session: Session,
    *,
    run_id: UUID,
    document: AnnouncementDocument | None,
) -> AnnouncementIntelligencePackage | None:
    if document is not None:
        package = session.execute(
            select(AnnouncementIntelligencePackage).where(
                AnnouncementIntelligencePackage.document_id == document.document_id
            )
        ).scalar_one_or_none()
        if package is not None:
            return package

    return session.execute(
        select(AnnouncementIntelligencePackage).where(AnnouncementIntelligencePackage.run_id == run_id)
    ).scalar_one_or_none()


def _match_delivery_targets(
    session: Session,
    *,
    source: AnnouncementSource | None,
) -> list[dict[str, object]]:
    allowed_target_ids = _parse_policy_target_ids(source)

    targets = session.execute(
        select(DeliveryTarget).where(DeliveryTarget.enabled.is_(True))
    ).scalars()

    matched_targets: list[dict[str, object]] = []
    for target in targets:
        if allowed_target_ids is not None and target.target_id not in allowed_target_ids:
            continue

        scene_names = target.config_json.get("scene_names")
        if isinstance(scene_names, list) and scene_names and "announcement" not in {
            str(item) for item in scene_names
        }:
            continue

        match_reason = "命中来源投递白名单"
        if allowed_target_ids is None:
            match_reason = (
                "命中场景配置"
                if isinstance(scene_names, list) and scene_names
                else "命中平台启用目标"
            )

        matched_targets.append(
            {
                "target_id": str(target.target_id),
                "name": target.name,
                "channel_type": target.channel_type,
                "match_reason": match_reason,
            }
        )

    matched_targets.sort(key=lambda item: (str(item["channel_type"]), str(item["name"])))
    return matched_targets


def _parse_policy_target_ids(source: AnnouncementSource | None) -> set[UUID] | None:
    if source is None:
        return None

    raw_ids = source.delivery_policy_json.get("target_ids")
    if not isinstance(raw_ids, list):
        return None

    parsed_ids: set[UUID] = set()
    for raw_id in raw_ids:
        try:
            parsed_ids.add(UUID(str(raw_id)))
        except (TypeError, ValueError):
            continue
    return parsed_ids


def _serialize_delivery_record(
    record: DeliveryRecord,
    target: DeliveryTarget | None,
) -> dict[str, object]:
    return {
        "record_id": str(record.record_id),
        "scene_name": record.scene_name,
        "source_ref_type": record.source_ref_type,
        "source_ref_id": str(record.source_ref_id) if record.source_ref_id is not None else None,
        "target_id": str(record.target_id) if record.target_id is not None else None,
        "target_name": target.name if target is not None else "未绑定目标",
        "channel_type": target.channel_type if target is not None else None,
        "status": record.status,
        "error_message": record.error_message,
        "created_at": record.created_at.isoformat(),
        "payload_summary": dict(record.payload_summary_json or {}),
    }


def _serialize_delivery_target(target: DeliveryTarget) -> dict[str, object]:
    config_json = dict(target.config_json or {})
    return {
        "target_id": str(target.target_id),
        "name": target.name,
        "channel_type": target.channel_type,
        "enabled": target.enabled,
        "config_json": config_json,
        "config_summary": config_json,
    }


def _normalize_delivery_target_name(name: str) -> str:
    normalized_name = name.strip()
    if not normalized_name:
        raise ValueError("投递目标名称不能为空")
    return normalized_name


def _normalize_delivery_channel_type(channel_type: str) -> str:
    normalized_channel_type = channel_type.strip().lower()
    if normalized_channel_type not in ALLOWED_DELIVERY_CHANNEL_TYPES:
        raise ValueError("投递渠道类型不支持")
    return normalized_channel_type


def _normalize_delivery_target_config(
    config_json: dict[str, object] | None,
) -> dict[str, object]:
    if config_json is None:
        return {}
    return dict(config_json)
