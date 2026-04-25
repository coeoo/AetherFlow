from __future__ import annotations

from typing import Any

from app.cve.browser.base import BrowserPageSnapshot
from app.cve.browser_agent_llm import LLMPageView
from app.cve.browser_agent_llm import NavigationContext
from app.cve.browser_agent_llm import build_llm_page_view
from app.cve.browser_agent_llm import build_navigation_context
from app.cve.browser_agent_llm import call_browser_agent_navigation


def build_navigation_page_view(
    snapshot: BrowserPageSnapshot,
    candidates: list[dict],
    *,
    cve_id: str = "",
    frontier_candidates: list[dict[str, object]] | None = None,
) -> LLMPageView:
    return build_llm_page_view(
        snapshot,
        candidates,
        cve_id=cve_id,
        frontier_candidates=frontier_candidates,
    )


def build_agent_navigation_context(
    state: dict,
    page_view: LLMPageView,
) -> NavigationContext:
    return build_navigation_context(state, page_view)


def request_navigation_decision(
    state: dict,
    *,
    snapshot: BrowserPageSnapshot,
    candidates: list[dict],
    frontier_candidates: list[dict[str, object]],
    llm_decision_log: list[dict[str, Any]] | None = None,
) -> tuple[NavigationContext, dict[str, Any]]:
    page_view = build_navigation_page_view(
        snapshot,
        candidates,
        cve_id=str(state.get("cve_id") or ""),
        frontier_candidates=frontier_candidates,
    )
    navigation_context = build_agent_navigation_context(state, page_view)
    decision = call_browser_agent_navigation(
        navigation_context,
        llm_decision_log=llm_decision_log,
    )
    return navigation_context, decision
