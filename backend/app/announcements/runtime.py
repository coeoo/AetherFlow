from __future__ import annotations

import hashlib
import html
import re
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.announcements.intelligence import classify_linux_relevance
from app.announcements.openwall_adapter import OpenwallAdapter
from app.models import (
    AnnouncementDocument,
    AnnouncementIntelligencePackage,
    AnnouncementRun,
    AnnouncementSource,
    SourceFetchRecord,
    TaskJob,
)
from app.platform.artifact_store import save_text_artifact


def fetch_url_content(url: str) -> str:
    response = httpx.get(url, timeout=10.0, follow_redirects=True)
    response.raise_for_status()
    return response.text


def execute_announcement_run(session: Session, *, run_id: UUID) -> None:
    run = session.get(AnnouncementRun, run_id)
    if run is None:
        raise RuntimeError(f"公告 run 不存在: {run_id}")

    try:
        existing_document = session.execute(
            select(AnnouncementDocument).where(AnnouncementDocument.run_id == run.run_id)
        ).scalar_one_or_none()
        if existing_document is not None:
            _finalize_existing_run(
                session,
                run=run,
                document=existing_document,
            )
            return

        input_snapshot = dict(run.input_snapshot_json or {})
        source_url = str(input_snapshot.get("source_url") or "").strip()
        raw_content = str(input_snapshot.get("raw_content") or "").strip()
        if not raw_content:
            if not source_url:
                raise RuntimeError("公告 run 缺少 source_url，无法抓取原文。")
            raw_content = fetch_url_content(source_url)

        run.stage = "normalize_text"
        source_artifact = save_text_artifact(
            session,
            scene_name="announcement",
            artifact_kind="source",
            source_url=source_url or None,
            filename_hint="source.html",
            content=raw_content,
            content_type="text/html; charset=utf-8",
            metadata={"run_id": str(run.run_id)},
        )

        normalized_text = normalize_text(raw_content)
        normalized_artifact = save_text_artifact(
            session,
            scene_name="announcement",
            artifact_kind="text",
            source_url=source_url or None,
            filename_hint="normalized.txt",
            content=normalized_text,
            content_type="text/plain; charset=utf-8",
            metadata={"run_id": str(run.run_id)},
        )

        title = (
            str(run.title_hint or "").strip()
            or str(input_snapshot.get("title") or "").strip()
            or extract_title(raw_content)
            or source_url
            or "未命名安全公告"
        )
        source_name = str(input_snapshot.get("source_name") or "Manual URL")
        published_at = parse_datetime(str(input_snapshot.get("published_at") or "").strip())

        run.stage = "build_package"
        document = AnnouncementDocument(
            run_id=run.run_id,
            source_id=run.source_id,
            title=title,
            source_name=source_name,
            source_url=source_url or None,
            published_at=published_at,
            language="zh-CN",
            source_item_key=_optional_str(input_snapshot.get("source_item_key")),
            content_dedup_hash=hashlib.sha256(normalized_text.encode("utf-8")).hexdigest(),
            source_artifact_id=source_artifact.artifact_id,
            normalized_text_artifact_id=normalized_artifact.artifact_id,
            content_excerpt=normalized_text[:300],
        )
        session.add(document)
        session.flush()

        linux_related, confidence, analyst_summary = classify_linux_relevance(
            title,
            normalized_text,
        )
        package = AnnouncementIntelligencePackage(
            run_id=run.run_id,
            document_id=document.document_id,
            confidence=confidence,
            severity="high" if linux_related else None,
            affected_products_json=[],
            iocs_json=[],
            remediation_json=[],
            evidence_json=[
                {
                    "kind": "excerpt",
                    "content": document.content_excerpt,
                }
            ],
            analyst_summary=analyst_summary,
            notify_recommended=linux_related,
        )
        session.add(package)

        run.summary_json = {
            "linux_related": linux_related,
            "confidence": confidence,
            "notify_recommended": linux_related,
            "primary_title": title,
        }
        run.status = "succeeded"
        run.stage = "finalize_run"
    except Exception as exc:
        run.status = "failed"
        run.summary_json = {
            "linux_related": None,
            "confidence": 0.0,
            "error": str(exc),
        }
        raise


def _finalize_existing_run(
    session: Session,
    *,
    run: AnnouncementRun,
    document: AnnouncementDocument,
) -> None:
    package = session.execute(
        select(AnnouncementIntelligencePackage).where(
            AnnouncementIntelligencePackage.document_id == document.document_id
        )
    ).scalar_one_or_none()

    if package is None:
        linux_related, confidence, analyst_summary = classify_linux_relevance(
            document.title,
            document.content_excerpt or "",
        )
        package = AnnouncementIntelligencePackage(
            run_id=run.run_id,
            document_id=document.document_id,
            confidence=confidence,
            severity="high" if linux_related else None,
            affected_products_json=[],
            iocs_json=[],
            remediation_json=[],
            evidence_json=[
                {
                    "kind": "excerpt",
                    "content": document.content_excerpt,
                }
            ],
            analyst_summary=analyst_summary,
            notify_recommended=linux_related,
        )
        session.add(package)
        session.flush()

    run.summary_json = {
        "linux_related": package.notify_recommended,
        "confidence": float(package.confidence),
        "notify_recommended": package.notify_recommended,
        "primary_title": document.title,
    }
    run.status = "succeeded"
    run.stage = "finalize_run"


def execute_monitor_fetch(session: Session, *, job: TaskJob) -> None:
    payload = dict(job.payload_json or {})
    source_id = payload.get("source_id")
    if source_id is None:
        raise RuntimeError("公告监控任务缺少 source_id。")

    source = session.get(AnnouncementSource, UUID(str(source_id)))
    if source is None:
        raise RuntimeError(f"公告监控源不存在: {source_id}")

    fetch_record = SourceFetchRecord(
        scene_name="announcement",
        source_id=source.source_id,
        source_type="announcement_monitor_fetch",
        source_ref=source.name,
        status="running",
        request_snapshot_json={
            "source_id": str(source.source_id),
            "source_type": source.source_type,
        },
        response_meta_json={},
    )
    session.add(fetch_record)
    session.flush()

    try:
        documents = load_source_documents(session, source=source)
        new_count = 0
        for document in documents:
            exists = session.execute(
                select(AnnouncementDocument.document_id).where(
                    AnnouncementDocument.source_id == source.source_id,
                    AnnouncementDocument.source_item_key == document["source_item_key"],
                )
            ).scalar_one_or_none()
            if exists is not None:
                continue

            job = TaskJob(
                scene_name="announcement",
                job_type="announcement_manual_extract",
                trigger_kind="monitor",
                status="queued",
                payload_json={
                    "input_mode": "url",
                    "source_url": document["source_url"],
                },
            )
            session.add(job)
            session.flush()

            run = AnnouncementRun(
                job_id=job.job_id,
                entry_mode="monitor_source",
                source_id=source.source_id,
                trigger_fetch_id=fetch_record.fetch_id,
                status="queued",
                stage="fetch_source",
                title_hint=document["title"],
                input_snapshot_json={
                    "input_mode": "url",
                    "source_url": document["source_url"],
                    "source_name": document["source_name"],
                    "source_type": document["source_type"],
                    "published_at": document["published_at"],
                    "source_item_key": document["source_item_key"],
                    "raw_content": document["raw_content"],
                },
                summary_json={},
            )
            session.add(run)
            session.flush()
            new_count += 1

        fetch_record.status = "succeeded"
        fetch_record.response_meta_json = {
            "discovered_count": len(documents),
            "new_count": new_count,
        }
    except Exception as exc:
        fetch_record.status = "failed"
        fetch_record.error_message = str(exc)
        fetch_record.response_meta_json = {
            "discovered_count": 0,
            "new_count": 0,
        }
        raise


def load_source_documents(
    session: Session,
    *,
    source: AnnouncementSource,
) -> list[dict[str, str]]:
    if source.source_type != "openwall":
        raise RuntimeError(f"暂不支持的公告来源类型: {source.source_type}")

    config = dict(source.config_json or {})
    adapter = OpenwallAdapter(
        days_back=int(config.get("days_back", 3)),
        max_documents=int(config.get("max_documents", 5)),
    )
    return adapter.fetch_documents()


def normalize_text(raw_content: str) -> str:
    no_tags = re.sub(r"<[^>]+>", " ", raw_content)
    unescaped = html.unescape(no_tags)
    lines = [line.strip() for line in unescaped.splitlines()]
    filtered = [line for line in lines if line]
    return "\n".join(filtered)


def extract_title(raw_content: str) -> str | None:
    title_match = re.search(
        r"<title>(.*?)</title>",
        raw_content,
        re.IGNORECASE | re.DOTALL,
    )
    if title_match is None:
        return None
    return html.unescape(title_match.group(1)).strip() or None


def parse_datetime(value: str) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
