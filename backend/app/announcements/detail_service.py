from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    AnnouncementDocument,
    AnnouncementIntelligencePackage,
    AnnouncementRun,
)
from app.announcements.delivery_service import get_announcement_delivery_panel


def get_announcement_run_detail(
    session: Session,
    *,
    run_id: UUID,
) -> dict[str, object] | None:
    run = session.get(AnnouncementRun, run_id)
    if run is None:
        return None

    document = session.execute(
        select(AnnouncementDocument).where(AnnouncementDocument.run_id == run.run_id)
    ).scalar_one_or_none()
    package = None
    if document is not None:
        package = session.execute(
            select(AnnouncementIntelligencePackage).where(
                AnnouncementIntelligencePackage.document_id == document.document_id
            )
        ).scalar_one_or_none()

    return {
        "run_id": str(run.run_id),
        "entry_mode": run.entry_mode,
        "status": run.status,
        "stage": run.stage,
        "summary": run.summary_json,
        "input_snapshot": dict(run.input_snapshot_json or {}),
        "document": _serialize_document(document),
        "package": _serialize_package(package),
        "delivery": get_announcement_delivery_panel(session, run_id=run.run_id),
    }


def _serialize_document(document: AnnouncementDocument | None) -> dict[str, object] | None:
    if document is None:
        return None

    return {
        "document_id": str(document.document_id),
        "title": document.title,
        "source_name": document.source_name,
        "source_url": document.source_url,
        "published_at": (
            document.published_at.isoformat() if document.published_at is not None else None
        ),
        "content_excerpt": document.content_excerpt,
    }


def _serialize_package(
    package: AnnouncementIntelligencePackage | None,
) -> dict[str, object] | None:
    if package is None:
        return None

    return {
        "package_id": str(package.package_id),
        "confidence": float(package.confidence),
        "severity": package.severity,
        "analyst_summary": package.analyst_summary,
        "notify_recommended": package.notify_recommended,
        "affected_products": list(package.affected_products_json or []),
        "iocs": list(package.iocs_json or []),
        "remediation": list(package.remediation_json or []),
        "evidence": list(package.evidence_json or []),
    }
