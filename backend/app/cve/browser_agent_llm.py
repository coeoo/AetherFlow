from __future__ import annotations

import json
from dataclasses import asdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from app import http_client
from app.config import load_settings
from app.cve.browser.base import BrowserPageSnapshot


MAX_KEY_LINKS = 15
_REQUIRED_DECISION_FIELDS = {
    "action",
    "reason_summary",
    "confirmed_page_role",
    "selected_urls",
    "selected_candidate_keys",
    "cross_domain_justification",
    "chain_updates",
    "new_chains",
}


@dataclass(frozen=True)
class LLMLink:
    url: str
    text: str
    context: str
    is_cross_domain: bool
    estimated_target_role: str


@dataclass(frozen=True)
class LLMPageView:
    url: str
    page_role: str
    title: str
    accessibility_tree_summary: str
    key_links: list[LLMLink]
    patch_candidates: list[dict[str, str]]
    page_text_summary: str


@dataclass(frozen=True)
class NavigationContext:
    cve_id: str
    budget_remaining: dict[str, int]
    navigation_path: list[str]
    parent_page_summary: str | None
    current_page: LLMPageView
    active_chains: list[dict]
    discovered_candidates: list[dict]
    visited_domains: list[str]


def build_llm_page_view(snapshot: BrowserPageSnapshot, candidates: list[dict]) -> LLMPageView:
    """从 BrowserPageSnapshot 构建可直接发给 LLM 的页面视图。"""
    key_links = [
        LLMLink(
            url=link.url,
            text=link.text,
            context=link.context,
            is_cross_domain=link.is_cross_domain,
            estimated_target_role=link.estimated_target_role,
        )
        for link in snapshot.links[:MAX_KEY_LINKS]
    ]
    return LLMPageView(
        url=snapshot.final_url or snapshot.url,
        page_role=snapshot.page_role_hint,
        title=snapshot.title,
        accessibility_tree_summary=snapshot.accessibility_tree,
        key_links=key_links,
        patch_candidates=[dict(candidate) for candidate in candidates],
        page_text_summary=snapshot.markdown_content,
    )


def build_navigation_context(state: dict, page_view: LLMPageView) -> NavigationContext:
    """从 AgentState 和页面视图构造完整导航上下文。"""
    visited_urls = [str(url) for url in list(state.get("visited_urls", []))]
    return NavigationContext(
        cve_id=str(state.get("cve_id", "")),
        budget_remaining=_coerce_budget(state.get("budget")),
        navigation_path=_build_navigation_path(state, page_view),
        parent_page_summary=_build_parent_page_summary(state),
        current_page=page_view,
        active_chains=[
            dict(chain)
            for chain in list(state.get("navigation_chains", []))
            if isinstance(chain, dict) and chain.get("status") == "in_progress"
        ],
        discovered_candidates=[dict(candidate) for candidate in list(state.get("direct_candidates", []))],
        visited_domains=_extract_visited_domains(visited_urls),
    )


def call_browser_agent_navigation(context: NavigationContext) -> dict[str, Any]:
    """调用 OpenAI 兼容接口获取浏览器导航决策。"""
    settings = load_settings()
    if not settings.llm_base_url or not settings.llm_api_key or not settings.llm_default_model:
        raise RuntimeError("missing_provider_config")

    response = http_client.post(
        f"{settings.llm_base_url.rstrip('/')}/chat/completions",
        timeout=float(settings.llm_timeout_seconds),
        headers={
            "Authorization": f"Bearer {settings.llm_api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": settings.llm_default_model,
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "system",
                    "content": _load_browser_navigation_prompt(),
                },
                {
                    "role": "user",
                    "content": json.dumps(asdict(context), ensure_ascii=False),
                },
            ],
        },
    )
    response.raise_for_status()
    payload = response.json()
    content = str(payload["choices"][0]["message"]["content"])
    decision = json.loads(content)
    if not isinstance(decision, dict):
        raise ValueError("browser_agent_navigation 返回结果不是 JSON object")
    missing_fields = sorted(_REQUIRED_DECISION_FIELDS - set(decision))
    if missing_fields:
        raise ValueError(f"browser_agent_navigation 缺少字段: {', '.join(missing_fields)}")
    decision["model_name"] = settings.llm_default_model
    return decision


def _load_browser_navigation_prompt() -> str:
    prompt_path = Path(__file__).resolve().parent / "prompts" / "browser_agent_navigation.md"
    return prompt_path.read_text(encoding="utf-8")


def _coerce_budget(raw_budget: object) -> dict[str, int]:
    if not isinstance(raw_budget, dict):
        return {}
    budget: dict[str, int] = {}
    for key, value in raw_budget.items():
        try:
            budget[str(key)] = int(value)
        except (TypeError, ValueError):
            continue
    return budget


def _build_navigation_path(state: dict, page_view: LLMPageView) -> list[str]:
    raw_history = list(state.get("page_role_history", []))
    navigation_path: list[str] = []
    for item in raw_history:
        if not isinstance(item, dict):
            continue
        role = str(item.get("role", "")).strip()
        url = str(item.get("url", "")).strip()
        if role and url:
            navigation_path.append(f"{role}: {url}")
    if not navigation_path:
        navigation_path.append(f"{page_view.page_role}: {page_view.url}")
    return navigation_path


def _build_parent_page_summary(state: dict) -> str | None:
    raw_history = [item for item in list(state.get("page_role_history", [])) if isinstance(item, dict)]
    if len(raw_history) < 2:
        return None

    parent_entry = raw_history[-2]
    parent_url = str(parent_entry.get("url", "")).strip()
    parent_role = str(parent_entry.get("role", "")).strip()
    snapshots = state.get("browser_snapshots", {})
    snapshot_data = snapshots.get(parent_url, {}) if isinstance(snapshots, dict) else {}
    if not isinstance(snapshot_data, dict):
        snapshot_data = {}
    title = str(snapshot_data.get("title", "")).strip()
    markdown_summary = str(snapshot_data.get("markdown_content", "")).strip()
    summary_parts = [part for part in [parent_role, title, markdown_summary] if part]
    if not summary_parts:
        return parent_url or None
    return " | ".join(summary_parts)


def _extract_visited_domains(visited_urls: list[str]) -> list[str]:
    domains: list[str] = []
    seen: set[str] = set()
    for url in visited_urls:
        domain = urlparse(url).netloc.lower()
        if not domain or domain in seen:
            continue
        seen.add(domain)
        domains.append(domain)
    return domains
