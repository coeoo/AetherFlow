from __future__ import annotations

from app.config import Settings
from app.db.session import create_session_factory
from app.platform.health_summary import collect_health_summary
from app.platform.tasks import get_latest_scene_status_by_scene, list_recent_platform_jobs
from app.announcements.delivery_service import list_platform_delivery_records

PLATFORM_TAGLINE = "把原始安全信号处理成可复查的结构化情报"


def collect_home_summary(settings: Settings) -> dict[str, object]:
    platform_name = settings.app_name.removesuffix(" API")
    health = collect_health_summary(settings)
    scenes = [
        {
            "scene_name": "cve",
            "title": "CVE 补丁检索",
            "description": "输入一个 CVE 编号，快速得到补丁线索、证据和 Diff。",
            "path": "/patch",
            "recent_status": "最近暂无运行",
        },
        {
            "scene_name": "announcement",
            "title": "安全公告提取",
            "description": "输入公告 URL 或进入监控视图，生成结构化情报包与投递建议。",
            "path": "/announcements",
            "recent_status": "最近暂无运行",
        },
    ]

    if not settings.database_url:
        return {
            "platform_name": platform_name,
            "platform_tagline": PLATFORM_TAGLINE,
            "scenes": scenes,
            "recent_jobs": [],
            "recent_deliveries": [],
            "health": health,
        }

    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        latest_scene_status = get_latest_scene_status_by_scene(session)
        recent_jobs = list_recent_platform_jobs(session, limit=10)
        recent_deliveries = list_platform_delivery_records(
            session,
            scene_name=None,
            status=None,
            channel_type=None,
            limit=10,
        )

    for scene in scenes:
        scene["recent_status"] = latest_scene_status.get(scene["scene_name"], "最近暂无运行")

    return {
        "platform_name": platform_name,
        "platform_tagline": PLATFORM_TAGLINE,
        "scenes": scenes,
        "recent_jobs": recent_jobs,
        "recent_deliveries": recent_deliveries,
        "health": health,
    }
