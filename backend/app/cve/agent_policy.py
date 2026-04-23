from __future__ import annotations

from dataclasses import dataclass
import os
from urllib.parse import urlparse


DEFAULT_PATCH_AGENT_BUDGET = {
    "max_pages_total": 20,
    "max_depth": 6,
    "max_cross_domain_expansions": 8,
    "max_children_per_node": 5,
    "max_parallel_frontier": 3,
    "max_agent_iterations": 15,
    "max_llm_calls": 15,
    "max_llm_tokens": 12000,
    "max_download_attempts": 8,
    "max_chains": 5,
}
ALLOWED_AGENT_ACTIONS = {
    "expand_frontier",
    "try_candidate_download",
    "stop_search",
    "needs_human_review",
}


def build_default_budget() -> dict[str, int]:
    budget = dict(DEFAULT_PATCH_AGENT_BUDGET)
    env_mapping = {
        "max_pages_total": "AETHERFLOW_CVE_MAX_PAGES_TOTAL",
        "max_depth": "AETHERFLOW_CVE_MAX_DEPTH",
        "max_cross_domain_expansions": "AETHERFLOW_CVE_MAX_CROSS_DOMAIN_EXPANSIONS",
        "max_children_per_node": "AETHERFLOW_CVE_MAX_CHILDREN_PER_NODE",
        "max_parallel_frontier": "AETHERFLOW_CVE_MAX_PARALLEL_FRONTIER",
        "max_agent_iterations": "AETHERFLOW_CVE_MAX_AGENT_ITERATIONS",
        "max_llm_calls": "AETHERFLOW_CVE_MAX_LLM_CALLS",
        "max_llm_tokens": "AETHERFLOW_CVE_MAX_LLM_TOKENS",
        "max_download_attempts": "AETHERFLOW_CVE_MAX_DOWNLOAD_ATTEMPTS",
        "max_chains": "AETHERFLOW_CVE_MAX_CHAINS",
    }
    for budget_key, env_name in env_mapping.items():
        raw_value = os.getenv(env_name)
        if raw_value is None:
            continue
        budget[budget_key] = int(raw_value)
    return budget


@dataclass(frozen=True)
class AgentValidationResult:
    accepted: bool
    normalized_action: str
    normalized_selected_urls: list[str]
    rejection_reason: str | None = None


@dataclass(frozen=True)
class StopEvaluation:
    should_stop: bool
    reason: str


def count_consumed_pages(state) -> int:
    page_observations = dict(state.get("page_observations") or {})
    if page_observations:
        return sum(
            1
            for observation in page_observations.values()
            if isinstance(observation, dict)
            and str(observation.get("fetch_status") or "") in {"fetched", "failed"}
        )
    return len(list(state.get("page_nodes") or []))


def _active_chains(state) -> list[dict]:
    return [
        chain
        for chain in list(state.get("navigation_chains") or [])
        if isinstance(chain, dict) and str(chain.get("status") or "") == "in_progress"
    ]


def unexpanded_frontier_items(state) -> list[dict]:
    return [
        item
        for item in list(state.get("frontier") or [])
        if isinstance(item, dict) and not item.get("expanded")
    ]


def _remaining_page_budget(state) -> int:
    budget = dict(state.get("budget") or {})
    return int(budget.get("max_pages_total", 0) or 0) - count_consumed_pages(state)


def _has_chain_derived_cross_domain_candidates(state) -> bool:
    active_chains = _active_chains(state)
    if not active_chains:
        return False

    expected_roles = {
        str(role)
        for chain in active_chains
        for role in list(chain.get("expected_next_roles") or [])
        if str(role).strip()
    }
    current_page_url = str(state.get("current_page_url") or "").strip()
    current_host = urlparse(current_page_url).hostname or current_page_url
    snapshots = dict(state.get("browser_snapshots") or {})
    current_snapshot = dict(snapshots.get(current_page_url) or {})
    for raw_link in list(current_snapshot.get("links") or []):
        if not isinstance(raw_link, dict):
            continue
        link_url = str(raw_link.get("url") or "").strip()
        if not link_url:
            continue
        link_host = urlparse(link_url).hostname or link_url
        if current_host and link_host == current_host:
            continue
        estimated_role = str(raw_link.get("estimated_target_role") or "").strip()
        if estimated_role and estimated_role in expected_roles:
            return True
    return False


def evaluate_stop_condition(state: dict) -> StopEvaluation:
    """
    规则0：已有下载成功的 patch → 无条件停止
    规则1：有活跃链路且预算未耗尽 → 不停
    规则2：有候选且所有链路已终止 → 停
    规则3：无活跃链路 + 无 frontier + 无候选 → 停
    """
    patches = list(state.get("patches") or [])
    if any(isinstance(p, dict) and p.get("download_status") == "downloaded" for p in patches):
        return StopEvaluation(should_stop=True, reason="patches_downloaded")

    active_chains = _active_chains(state)
    if active_chains and _remaining_page_budget(state) > 0:
        return StopEvaluation(should_stop=False, reason="active_chains_in_progress")

    direct_candidates = list(state.get("direct_candidates") or [])
    if direct_candidates and not active_chains:
        return StopEvaluation(should_stop=True, reason="all_chains_resolved")

    if not active_chains and not unexpanded_frontier_items(state) and not direct_candidates:
        return StopEvaluation(should_stop=True, reason="no_remaining_frontier_or_candidates")

    if _remaining_page_budget(state) <= 0:
        return StopEvaluation(should_stop=True, reason="max_pages_total_exhausted")

    return StopEvaluation(should_stop=False, reason="frontier_or_candidates_remaining")


def validate_needs_human_review(state: dict) -> bool:
    """
    仅当同时满足以下条件时接受 needs_human_review：
    1. 没有活跃链路
    2. 没有未扩展 frontier
    3. 没有链路推导出的跨域候选
    """
    if _active_chains(state):
        return False
    if unexpanded_frontier_items(state):
        return False
    if _has_chain_derived_cross_domain_candidates(state):
        return False
    return True


def validate_agent_decision(state, decision: dict) -> AgentValidationResult:
    action = str(decision.get("action") or "").strip()
    if action not in ALLOWED_AGENT_ACTIONS:
        return AgentValidationResult(
            accepted=False,
            normalized_action="stop_search",
            normalized_selected_urls=[],
            rejection_reason="invalid_action",
        )

    budget = dict(state.get("budget") or {})
    consumed_pages = count_consumed_pages(state)
    if consumed_pages >= int(budget.get("max_pages_total", 0) or 0):
        return AgentValidationResult(
            accepted=False,
            normalized_action="stop_search",
            normalized_selected_urls=[],
            rejection_reason="max_pages_total_exhausted",
        )

    frontier_urls = {
        str(item.get("url"))
        for item in list(state.get("frontier") or [])
        if isinstance(item, dict) and item.get("url")
    }
    current_page_url = str(state.get("current_page_url") or "").strip()
    page_observations = dict(state.get("page_observations") or {})
    if not current_page_url and page_observations:
        current_page_url = str(next(iter(page_observations.keys())))

    current_observation = dict(page_observations.get(current_page_url) or {})
    current_page_candidate_urls = {
        str(item.get("url") or "").strip()
        for item in list(current_observation.get("frontier_candidates") or [])
        if isinstance(item, dict) and str(item.get("url") or "").strip()
    }
    if not current_page_candidate_urls:
        current_page_candidate_urls = {
            str(url).strip()
            for url in list(current_observation.get("extracted_links") or [])
            if isinstance(url, str) and str(url).strip()
        }

    allowed_urls = frontier_urls | current_page_candidate_urls
    selected_urls = [
        str(url).strip()
        for url in list(decision.get("selected_urls") or [])
        if str(url).strip()
    ]
    selected_candidate_keys = [
        str(key).strip()
        for key in list(decision.get("selected_candidate_keys") or [])
        if str(key).strip()
    ]
    available_candidate_keys = {
        str(candidate.get("canonical_key") or "").strip()
        for candidate in list(state.get("direct_candidates") or [])
        if isinstance(candidate, dict) and str(candidate.get("canonical_key") or "").strip()
    }

    for selected_url in selected_urls:
        if selected_url not in allowed_urls:
            return AgentValidationResult(
                accepted=False,
                normalized_action="stop_search",
                normalized_selected_urls=[],
                rejection_reason="selected_url_not_in_current_page_or_frontier",
            )

    visited_urls = {str(url) for url in list(state.get("visited_urls") or [])}
    for selected_url in selected_urls:
        if selected_url in visited_urls:
            return AgentValidationResult(
                accepted=False,
                normalized_action="stop_search",
                normalized_selected_urls=[],
                rejection_reason="duplicate_url",
            )

    if action == "try_candidate_download" and not selected_candidate_keys:
        return AgentValidationResult(
            accepted=False,
            normalized_action="stop_search",
            normalized_selected_urls=[],
            rejection_reason="missing_selected_candidate_keys",
        )

    for selected_candidate_key in selected_candidate_keys:
        if selected_candidate_key not in available_candidate_keys:
            return AgentValidationResult(
                accepted=False,
                normalized_action="stop_search",
                normalized_selected_urls=[],
                rejection_reason="selected_candidate_key_not_in_candidates",
            )

    current_host = urlparse(current_page_url).hostname or current_page_url
    cross_domain_urls = [
        url
        for url in selected_urls
        if current_host and (urlparse(url).hostname or url) not in {"", current_host}
    ]
    remaining_cross_domain_budget = int(budget.get("max_cross_domain_expansions", 0) or 0)
    if len(cross_domain_urls) > remaining_cross_domain_budget:
        return AgentValidationResult(
            accepted=False,
            normalized_action="stop_search",
            normalized_selected_urls=[],
            rejection_reason="cross_domain_budget_exhausted",
        )

    if cross_domain_urls:
        state["budget"]["max_cross_domain_expansions"] = (
            remaining_cross_domain_budget - len(cross_domain_urls)
        )
        state["cross_domain_hops"] = int(state.get("cross_domain_hops", 0)) + len(
            cross_domain_urls
        )

    return AgentValidationResult(
        accepted=True,
        normalized_action=action,
        normalized_selected_urls=selected_urls,
        rejection_reason=None,
    )
