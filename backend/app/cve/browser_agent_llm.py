from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
import json
from time import perf_counter
from dataclasses import asdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
import httpx
import re

from app import http_client
from app.config import load_settings
from app.cve.browser.base import BrowserPageSnapshot, PageLink


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
_CVE_ID_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


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


def _score_link_for_llm(link: PageLink, *, cve_id: str = "") -> int:
    """为页面链接计算 LLM 可见性优先级分数。"""
    role_scores = {
        "commit_page": 100,
        "pull_request_page": 100,
        "download_page": 80,
        "tracker_page": 60,
        "bugtracker_page": 60,
        "advisory_page": 40,
        "repository_page": 20,
    }
    score = role_scores.get(link.estimated_target_role, 0)
    if link.is_cross_domain:
        score += 10
    normalized_url = link.url.lower()
    if any(keyword in normalized_url for keyword in ("commit", "patch", "diff", "merge_request", "pull")):
        score += 30
    target_cve_id = str(cve_id or "").strip().upper()
    if target_cve_id:
        matched_cve_ids = {
            matched.upper()
            for matched in _CVE_ID_RE.findall(
                f"{link.url}\n{link.text}\n{link.context}"
            )
        }
        if target_cve_id in matched_cve_ids:
            score += 120
        elif matched_cve_ids:
            score -= 160
    return score


def build_llm_page_view(
    snapshot: BrowserPageSnapshot,
    candidates: list[dict],
    *,
    cve_id: str = "",
    frontier_candidates: list[dict[str, object]] | None = None,
) -> LLMPageView:
    """从 BrowserPageSnapshot 构建可直接发给 LLM 的页面视图。"""
    if frontier_candidates:
        page_host = urlparse(snapshot.final_url or snapshot.url).hostname or snapshot.final_url or snapshot.url
        sorted_candidates = sorted(
            [candidate for candidate in frontier_candidates if isinstance(candidate, dict)],
            key=lambda candidate: int(candidate.get("score", 0) or 0),
            reverse=True,
        )
        key_links = [
            LLMLink(
                url=str(candidate.get("url") or ""),
                text=str(candidate.get("anchor_text") or ""),
                context=str(candidate.get("link_context") or ""),
                is_cross_domain=(urlparse(str(candidate.get("url") or "")).hostname or str(candidate.get("url") or "")) != page_host,
                estimated_target_role=str(candidate.get("page_role") or ""),
            )
            for candidate in sorted_candidates[:MAX_KEY_LINKS]
            if str(candidate.get("url") or "").strip()
        ]
    else:
        ranked_links = sorted(
            snapshot.links,
            key=lambda link: _score_link_for_llm(link, cve_id=cve_id),
            reverse=True,
        )
        key_links = [
            LLMLink(
                url=link.url,
                text=link.text,
                context=link.context,
                is_cross_domain=link.is_cross_domain,
                estimated_target_role=link.estimated_target_role,
            )
            for link in ranked_links[:MAX_KEY_LINKS]
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
    context = NavigationContext(
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
    return context


def call_browser_agent_navigation(
    context: NavigationContext,
    *,
    llm_decision_log: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """调用 OpenAI 兼容接口获取浏览器导航决策。"""
    settings = load_settings()
    if not settings.llm_base_url or not settings.llm_api_key or not settings.llm_default_model:
        raise RuntimeError("missing_provider_config")

    started_at = perf_counter()
    response = None
    last_error: Exception | None = None
    max_attempts = max(1, int(settings.llm_retry_attempts))
    request_timeout: float | None
    wall_clock_timeout = max(1, int(settings.llm_wall_clock_timeout_seconds or 120))
    if int(settings.llm_timeout_seconds) <= 0:
        request_timeout = None
    else:
        request_timeout = float(settings.llm_timeout_seconds)
    request_body: dict[str, object] = {
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
    }
    if settings.llm_reasoning_effort:
        request_body["reasoning_effort"] = settings.llm_reasoning_effort
    for attempt_index in range(max_attempts):
        try:
            executor = ThreadPoolExecutor(max_workers=1)
            try:
                future = executor.submit(
                    http_client.post,
                    f"{settings.llm_base_url.rstrip('/')}/chat/completions",
                    timeout=request_timeout,
                    headers={
                        "Authorization": f"Bearer {settings.llm_api_key}",
                        "Content-Type": "application/json",
                    },
                    json=request_body,
                )
                try:
                    response = future.result(timeout=wall_clock_timeout)
                except FutureTimeoutError as exc:
                    future.cancel()
                    raise httpx.ReadTimeout(
                        f"LLM 调用超过总时限 {wall_clock_timeout}s"
                    ) from exc
            finally:
                executor.shutdown(wait=False, cancel_futures=True)
            break
        except Exception as exc:
            last_error = exc
            if attempt_index + 1 >= max_attempts:
                _append_llm_failure_log(
                    llm_decision_log,
                    context=context,
                    error=exc,
                    model_name=settings.llm_default_model,
                    latency_ms=int((perf_counter() - started_at) * 1000),
                )
                raise

    if response is None:
        if last_error is not None:
            raise last_error
        raise RuntimeError("llm_request_failed_without_response")
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
    _append_llm_decision_log(
        llm_decision_log,
        context=context,
        decision=decision,
        model_name=settings.llm_default_model,
        latency_ms=int((perf_counter() - started_at) * 1000),
    )
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


def _append_llm_decision_log(
    log: list[dict[str, Any]] | None,
    *,
    context: NavigationContext,
    decision: dict[str, Any],
    model_name: str,
    latency_ms: int,
) -> None:
    if not isinstance(log, list):
        return

    selected_urls = [
        str(item).strip()
        for item in list(decision.get("selected_urls", []))
        if str(item).strip()
    ]
    page_domain = urlparse(context.current_page.url).netloc.lower()
    log.append(
        {
            "cve_id": context.cve_id,
            "step_index": len(log) + 1,
            "page_url": context.current_page.url,
            "page_role": context.current_page.page_role,
            "action": str(decision.get("action", "")),
            "selected_urls": selected_urls,
            "selected_candidate_keys": [
                str(item)
                for item in list(decision.get("selected_candidate_keys", []))
                if str(item).strip()
            ],
            "reason_summary": str(decision.get("reason_summary", "")),
            "cross_domain": any(
                urlparse(selected_url).netloc.lower() != page_domain
                for selected_url in selected_urls
            ),
            "latency_ms": max(0, latency_ms),
            "model_name": model_name,
        }
    )


def _append_llm_failure_log(
    log: list[dict[str, Any]] | None,
    *,
    context: NavigationContext,
    error: Exception,
    model_name: str,
    latency_ms: int,
) -> None:
    if not isinstance(log, list):
        return
    log.append(
        {
            "cve_id": context.cve_id,
            "step_index": len(log) + 1,
            "page_url": context.current_page.url,
            "page_role": context.current_page.page_role,
            "action": "llm_call_failed",
            "selected_urls": [],
            "selected_candidate_keys": [],
            "reason_summary": str(error),
            "cross_domain": False,
            "latency_ms": max(0, latency_ms),
            "model_name": model_name,
            "error_type": type(error).__name__,
        }
    )
