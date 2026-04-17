from __future__ import annotations

from datetime import UTC, datetime
import ipaddress
import socket
from urllib.parse import urlparse
from uuid import UUID

import httpx
from sqlalchemy import Select, select
from sqlalchemy.orm import Session, sessionmaker

from app.models import DeliveryRecord, DeliveryTarget

ALLOWED_DELIVERY_CHANNEL_TYPES = {"email", "wecom", "webhook"}
ALLOWED_DELIVERY_KINDS = {"production", "test"}
ALLOWED_DELIVERY_STATUSES = {"queued", "sending", "sent", "failed", "skipped"}


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
    normalized_channel_type = _normalize_delivery_channel_type(channel_type)
    target = DeliveryTarget(
        name=_normalize_delivery_target_name(name),
        channel_type=normalized_channel_type,
        enabled=enabled,
        config_json=_normalize_delivery_target_config(
            config_json,
            channel_type=normalized_channel_type,
        ),
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
    target = session.get(DeliveryTarget, UUID(str(target_id)))
    if target is None:
        raise LookupError("投递目标不存在")

    if name is not None:
        target.name = _normalize_delivery_target_name(name)
    if channel_type is not None:
        target.channel_type = _normalize_delivery_channel_type(channel_type)
    if enabled is not None:
        target.enabled = enabled
    if config_json is not None:
        target.config_json = _normalize_delivery_target_config(
            config_json,
            channel_type=target.channel_type,
        )
    target.updated_at = _utcnow()
    session.flush()
    return _serialize_delivery_target(target)


def list_platform_delivery_records(
    session: Session,
    *,
    scene_name: str | None,
    status: str | None,
    channel_type: str | None,
    delivery_kind: str | None,
    limit: int,
) -> list[dict[str, object]]:
    query = _delivery_record_query()
    if scene_name:
        query = query.where(DeliveryRecord.scene_name == scene_name)
    if status:
        query = query.where(DeliveryRecord.status == status)
    if channel_type:
        query = query.where(DeliveryTarget.channel_type == channel_type)
    if delivery_kind:
        query = query.where(DeliveryRecord.delivery_kind == delivery_kind)

    rows = session.execute(query).all()
    records = [_serialize_delivery_record(record, target) for record, target in rows]
    records.sort(key=lambda item: str(item["created_at"]), reverse=True)
    return records[:limit]


def create_test_delivery_record(
    session: Session,
    *,
    target_id: UUID | str,
    payload_summary: dict[str, object] | None = None,
) -> dict[str, object]:
    target = session.get(DeliveryTarget, UUID(str(target_id)))
    if target is None:
        raise LookupError("投递目标不存在")
    if not target.enabled:
        raise ValueError("禁用目标不允许测试发送")

    summary = {
        "title": "平台测试发送",
        "message": "AetherFlow 平台投递测试消息",
    }
    summary.update(dict(payload_summary or {}))

    record = DeliveryRecord(
        target_id=target.target_id,
        scene_name="platform",
        source_ref_type="delivery_target",
        source_ref_id=target.target_id,
        delivery_kind="test",
        status="queued",
        payload_summary_json=summary,
        response_snapshot_json={"mode": "test_send"},
    )
    session.add(record)
    session.flush()
    return _execute_delivery_record(session, record=record, allow_disabled_target=False, clear_schedule=True)


def send_delivery_record_now(session: Session, *, record_id: UUID | str) -> dict[str, object]:
    record = _load_delivery_record(session, record_id=record_id, for_update=True)
    if record.status != "queued":
        raise ValueError("只有 queued 状态的投递记录可以立即发送")
    return _execute_delivery_record(
        session,
        record=record,
        allow_disabled_target=False,
        clear_schedule=True,
    )


def retry_delivery_record(session: Session, *, record_id: UUID | str) -> dict[str, object]:
    record = _load_delivery_record(session, record_id=record_id, for_update=True)
    if record.status != "failed":
        raise ValueError("只有 failed 状态的投递记录可以重试")
    return _execute_delivery_record(
        session,
        record=record,
        allow_disabled_target=False,
        clear_schedule=True,
    )


def schedule_delivery_record(
    session: Session,
    *,
    record_id: UUID | str,
    scheduled_at: datetime,
) -> dict[str, object]:
    record = _load_delivery_record(session, record_id=record_id, for_update=True)
    if record.delivery_kind != "production":
        raise ValueError("只有正式投递记录支持计划发送")
    if record.status != "queued":
        raise ValueError("只有 queued 状态的投递记录可以设置计划发送时间")

    resolved_scheduled_at = _normalize_datetime(scheduled_at)
    record.scheduled_at = resolved_scheduled_at
    record.updated_at = _utcnow()
    session.flush()
    target = session.get(DeliveryTarget, record.target_id) if record.target_id is not None else None
    return _serialize_delivery_record(record, target)


def process_scheduled_delivery_records(
    session_factory: sessionmaker[Session],
    *,
    limit: int = 20,
) -> int:
    processed_count = 0
    for _ in range(limit):
        with session_factory() as session, session.begin():
            record = _claim_next_due_delivery_record(session)
            if record is None:
                break
            _execute_delivery_record(
                session,
                record=record,
                allow_disabled_target=False,
                clear_schedule=True,
            )
            processed_count += 1
    return processed_count


def _claim_next_due_delivery_record(session: Session) -> DeliveryRecord | None:
    return session.scalar(
        select(DeliveryRecord)
        .where(
            DeliveryRecord.delivery_kind == "production",
            DeliveryRecord.status == "queued",
            DeliveryRecord.scheduled_at.is_not(None),
            DeliveryRecord.scheduled_at <= _utcnow(),
        )
        .order_by(DeliveryRecord.scheduled_at, DeliveryRecord.created_at, DeliveryRecord.record_id)
        .limit(1)
        .with_for_update(skip_locked=True)
    )


def _load_delivery_record(
    session: Session,
    *,
    record_id: UUID | str,
    for_update: bool,
) -> DeliveryRecord:
    query = select(DeliveryRecord).where(DeliveryRecord.record_id == UUID(str(record_id)))
    if for_update:
        query = query.with_for_update()
    record = session.scalar(query)
    if record is None:
        raise LookupError("投递记录不存在")
    return record


def _execute_delivery_record(
    session: Session,
    *,
    record: DeliveryRecord,
    allow_disabled_target: bool,
    clear_schedule: bool,
) -> dict[str, object]:
    target = session.get(DeliveryTarget, record.target_id) if record.target_id is not None else None
    if target is None:
        raise ValueError("投递记录未绑定有效目标")

    now = _utcnow()
    if clear_schedule:
        record.scheduled_at = None
    record.status = "sending"
    record.error_message = None
    record.updated_at = now
    session.flush()

    if not allow_disabled_target and not target.enabled:
        record.status = "skipped"
        record.error_message = None
        record.response_snapshot_json = {
            "channel_type": target.channel_type,
            "message": "目标已禁用，当前投递被跳过。",
        }
        record.updated_at = _utcnow()
        session.flush()
        return _serialize_delivery_record(record, target)

    try:
        response_snapshot = _send_delivery(target=target, record=record)
    except Exception as exc:
        failure_message = _build_failure_message(exc)
        record.status = "failed"
        record.sent_at = None
        record.error_message = failure_message
        record.response_snapshot_json = {
            "channel_type": target.channel_type,
            "message": failure_message,
        }
        record.updated_at = _utcnow()
        session.flush()
        return _serialize_delivery_record(record, target)

    record.status = "sent"
    record.sent_at = _utcnow()
    record.error_message = None
    record.response_snapshot_json = response_snapshot
    record.updated_at = _utcnow()
    session.flush()
    return _serialize_delivery_record(record, target)


def _send_delivery(
    *,
    target: DeliveryTarget,
    record: DeliveryRecord,
) -> dict[str, object]:
    delivery_url = _resolve_delivery_url(target)
    payload = _build_channel_payload(record)
    response = httpx.post(delivery_url, json=payload, timeout=10.0)
    response.raise_for_status()

    return {
        "channel_type": target.channel_type,
        "status_code": response.status_code,
        "target_summary": _summarize_delivery_url(delivery_url),
    }


def _build_channel_payload(record: DeliveryRecord) -> dict[str, object]:
    payload_summary = dict(record.payload_summary_json or {})
    title = str(payload_summary.get("title") or "未命名投递")
    message = payload_summary.get("message") or payload_summary.get("analyst_summary") or title
    return {
        "record_id": str(record.record_id),
        "scene_name": record.scene_name,
        "delivery_kind": record.delivery_kind,
        "source_ref_type": record.source_ref_type,
        "source_ref_id": str(record.source_ref_id) if record.source_ref_id is not None else None,
        "title": title,
        "message": str(message),
        "payload_summary": payload_summary,
    }


def _resolve_delivery_url(target: DeliveryTarget) -> str:
    config_json = dict(target.config_json or {})
    if target.channel_type == "wecom":
        url = config_json.get("webhook_url") or config_json.get("url")
    elif target.channel_type == "webhook":
        url = config_json.get("url") or config_json.get("webhook_url")
    else:
        url = (
            config_json.get("endpoint_url")
            or config_json.get("url")
            or config_json.get("webhook_url")
        )
        if not url:
            raise ValueError("邮件渠道当前未配置可用发送端点")

    resolved_url = str(url).strip() if url is not None else ""
    if not resolved_url:
        raise ValueError("投递目标缺少可用发送地址")
    _validate_delivery_url(resolved_url)
    return resolved_url


def _validate_delivery_url(raw_url: str) -> None:
    parsed = urlparse(raw_url)
    if parsed.scheme.lower() != "https":
        raise ValueError("投递目标地址必须使用 https")

    if parsed.username or parsed.password:
        raise ValueError("投递目标地址不允许包含认证信息")

    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        raise ValueError("投递目标地址缺少有效 host")

    if hostname in {"localhost"} or hostname.endswith(".localhost"):
        raise ValueError("投递目标地址不允许指向本机、内网或保留地址")

    resolved_ips = _resolve_host_ips(hostname)
    if not resolved_ips:
        raise ValueError("投递目标地址无法解析到有效公网地址")

    for resolved_ip in resolved_ips:
        ip = ipaddress.ip_address(resolved_ip)
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            raise ValueError("投递目标地址不允许指向本机、内网或保留地址")


def _resolve_host_ips(hostname: str) -> set[str]:
    try:
        infos = socket.getaddrinfo(hostname, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return set()

    resolved_ips: set[str] = set()
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        resolved_ips.add(str(sockaddr[0]))
    return resolved_ips


def _summarize_delivery_url(raw_url: str) -> str:
    parsed = urlparse(raw_url)
    path = parsed.path or ""
    if path == "/":
        path = ""
    return f"{parsed.scheme.lower()}://{parsed.hostname or ''}{path}"


def _build_failure_message(exc: Exception) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        return "投递请求返回非成功状态码"
    if isinstance(exc, httpx.RequestError):
        return "投递请求失败，请检查目标配置或网络连通性"
    return str(exc)


def _delivery_record_query() -> Select:
    return (
        select(DeliveryRecord, DeliveryTarget)
        .join(DeliveryTarget, DeliveryTarget.target_id == DeliveryRecord.target_id, isouter=True)
    )


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
        "delivery_kind": record.delivery_kind,
        "status": record.status,
        "error_message": record.error_message,
        "scheduled_at": record.scheduled_at.isoformat() if record.scheduled_at is not None else None,
        "sent_at": record.sent_at.isoformat() if record.sent_at is not None else None,
        "created_at": record.created_at.isoformat(),
        "payload_summary": dict(record.payload_summary_json or {}),
        "response_snapshot": dict(record.response_snapshot_json or {}),
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
    *,
    channel_type: str,
) -> dict[str, object]:
    normalized_config = dict(config_json or {})
    delivery_url = _extract_delivery_url(normalized_config, channel_type=channel_type)
    if delivery_url is not None:
        _validate_delivery_url(delivery_url)
    return normalized_config


def _extract_delivery_url(
    config_json: dict[str, object],
    *,
    channel_type: str,
) -> str | None:
    if channel_type == "wecom":
        candidate = config_json.get("webhook_url") or config_json.get("url")
    elif channel_type == "webhook":
        candidate = config_json.get("url") or config_json.get("webhook_url")
    else:
        candidate = (
            config_json.get("endpoint_url")
            or config_json.get("url")
            or config_json.get("webhook_url")
        )

    if candidate is None:
        return None
    return str(candidate).strip()


def _normalize_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _utcnow() -> datetime:
    return datetime.now(UTC)
