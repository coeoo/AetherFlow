from __future__ import annotations

from urllib.parse import urlparse

from app.cve.agent_policy import unexpanded_frontier_items
from app.cve.frontier_planner import normalize_frontier_url
from app.cve.agent_search_tools import coerce_rank
from app.cve.agent_search_tools import should_skip_frontier_link
from app.cve.agent_search_tools import textual_fix_signal_score
from app.cve.agent_state import AgentState
from app.cve.browser.base import PageLink
from app.cve.browser.page_role_classifier import classify_page_role
from app.cve.reference_matcher import get_candidate_priority

STAGE_FALLBACK_TARGET_ROLES_BY_SOURCE = {
    "tracker_page": [
        "commit_page",
        "pull_request_page",
        "merge_request_page",
        "download_page",
        "mailing_list_page",
    ],
    "mailing_list_page": [
        "commit_page",
        "pull_request_page",
        "merge_request_page",
        "download_page",
        "tracker_page",
        "bugtracker_page",
    ],
    "bugtracker_page": [
        "commit_page",
        "pull_request_page",
        "merge_request_page",
        "download_page",
    ],
    "repository_page": [
        "commit_page",
        "pull_request_page",
        "merge_request_page",
        "download_page",
    ],
    "advisory_page": [
        "tracker_page",
        "bugtracker_page",
        "commit_page",
        "pull_request_page",
        "merge_request_page",
        "download_page",
    ],
}

FALLBACK_ROLE_PRIORITY = {
    "commit_page": 0,
    "pull_request_page": 1,
    "merge_request_page": 1,
    "download_page": 2,
    "tracker_page": 3,
    "bugtracker_page": 4,
    "advisory_page": 5,
    "mailing_list_page": 6,
    "repository_page": 7,
    "unknown_page": 8,
}


def select_fallback_frontier_urls(
    state: AgentState,
    frontier_items: list[dict[str, object]],
) -> list[str]:
    raw_current_page_url = str(state.get("current_page_url") or "").strip()
    current_page_url = normalize_frontier_url(raw_current_page_url) or raw_current_page_url
    current_host = urlparse(current_page_url).hostname or current_page_url
    current_page_role = classify_page_role(current_page_url) if current_page_url else ""
    snapshots = dict(state.get("browser_snapshots") or {})
    current_snapshot = dict(snapshots.get(raw_current_page_url) or snapshots.get(current_page_url) or {})
    if current_snapshot:
        current_page_role = str(current_snapshot.get("page_role_hint") or current_page_role)
    stage_role_order = {
        role: index
        for index, role in enumerate(
            STAGE_FALLBACK_TARGET_ROLES_BY_SOURCE.get(current_page_role, [])
        )
    }
    visited_urls = {
        normalize_frontier_url(str(url)) or str(url).strip()
        for url in state.get("visited_urls", [])
        if str(url).strip()
    }
    max_children = int(state["budget"].get("max_children_per_node", 1) or 1)
    remaining_cross_domain_budget = int(
        state["budget"].get("max_cross_domain_expansions", 0) or 0
    )

    same_domain_urls: list[tuple[int, int, int, str]] = []
    same_domain_unknown_urls: list[tuple[int, int, int, str]] = []
    cross_domain_urls: list[tuple[int, int, int, str]] = []
    seen_urls: set[str] = set()

    for item in frontier_items:
        raw_url = str(item.get("url") or "").strip()
        url = normalize_frontier_url(raw_url) or raw_url
        if (
            not url
            or url == current_page_url
            or url in seen_urls
            or url in visited_urls
        ):
            continue
        synthetic_link = PageLink(
            url=url,
            text=str(item.get("anchor_text") or ""),
            context=str(item.get("link_context") or ""),
            is_cross_domain=(urlparse(url).hostname or url) != current_host,
            estimated_target_role=str(item.get("page_role") or ""),
        )
        if should_skip_frontier_link(current_page_role, synthetic_link):
            continue
        seen_urls.add(url)
        item_host = urlparse(url).hostname or url
        item_role = str(item.get("page_role") or synthetic_link.estimated_target_role or "").strip()
        item_role_rank = coerce_rank(item.get("_target_role_rank"))
        if item_role_rank == 999 and item_role in FALLBACK_ROLE_PRIORITY:
            item_role_rank = FALLBACK_ROLE_PRIORITY[item_role]
        item_score = int(item.get("score", 0) or 0)
        item_text_score = textual_fix_signal_score(item)
        if current_host and item_host == current_host:
            target_bucket = (
                same_domain_unknown_urls
                if current_page_role == "unknown_page" and item_role == "unknown_page"
                else same_domain_urls
            )
            target_bucket.append((item_role_rank, -item_score, -item_text_score, url))
        else:
            if item_role in stage_role_order:
                item_role_rank = stage_role_order[item_role]
            cross_domain_urls.append((item_role_rank, -item_score, -item_text_score, url))

    same_domain_urls.sort()
    same_domain_unknown_urls.sort()
    cross_domain_urls.sort()
    if remaining_cross_domain_budget > 0 and cross_domain_urls:
        best_cross_domain_rank = cross_domain_urls[0][0]
        cross_domain_urls = [
            item for item in cross_domain_urls if item[0] == best_cross_domain_rank
        ]
    if cross_domain_urls and (
        not same_domain_urls or cross_domain_urls[0][:3] < same_domain_urls[0][:3]
    ):
        selected_urls = [
            url
            for _, _, _, url in cross_domain_urls[: min(max_children, remaining_cross_domain_budget)]
        ]
    else:
        selected_urls = [url for _, _, _, url in same_domain_urls[:max_children]]
    if not selected_urls and same_domain_unknown_urls:
        selected_urls = [url for _, _, _, url in same_domain_unknown_urls[:max_children]]
    remaining_slots = max_children - len(selected_urls)
    if remaining_slots > 0 and remaining_cross_domain_budget > 0:
        selected_urls.extend(
            [
                url
                for _, _, _, url in cross_domain_urls[
                    : min(remaining_slots, remaining_cross_domain_budget)
                ]
                if url not in selected_urls and not selected_urls
            ]
        )
    if remaining_slots > 0 and not selected_urls:
        selected_urls.extend(
            [
                url
                for _, _, _, url in same_domain_unknown_urls[:remaining_slots]
                if url not in selected_urls
            ]
        )
    return selected_urls


def candidate_priority(candidate: dict) -> int:
    """从候选 dict 获取质量优先级。"""
    patch_type = str(candidate.get("patch_type") or candidate.get("candidate_type") or "")
    candidate_url = str(candidate.get("candidate_url") or "")
    return get_candidate_priority(patch_type, candidate_url)


def select_chain_guided_frontier_urls(
    state: AgentState,
    frontier_items: list[dict[str, object]],
) -> list[str]:
    active_chains = [
        chain
        for chain in list(state.get("navigation_chains") or [])
        if isinstance(chain, dict) and str(chain.get("status") or "") == "in_progress"
    ]
    expected_roles: list[str] = []
    seen_expected_roles: set[str] = set()
    for chain in active_chains:
        for raw_role in list(chain.get("expected_next_roles") or []):
            role = str(raw_role).strip()
            if not role or role in seen_expected_roles:
                continue
            expected_roles.append(role)
            seen_expected_roles.add(role)
    if not expected_roles:
        return []

    prioritized_items = filter_frontier_items_by_target_roles(
        state,
        frontier_items,
        target_roles=expected_roles,
    )
    if not prioritized_items:
        return []
    return select_fallback_frontier_urls(state, prioritized_items)


def target_roles_for_current_stage(state: AgentState) -> list[str]:
    current_page_url = str(state.get("current_page_url") or "").strip()
    current_role = ""
    if current_page_url:
        current_role = classify_page_role(current_page_url)
    snapshots = dict(state.get("browser_snapshots") or {})
    current_snapshot = dict(snapshots.get(current_page_url) or {})
    if current_snapshot:
        current_role = str(current_snapshot.get("page_role_hint") or current_role)
    return list(STAGE_FALLBACK_TARGET_ROLES_BY_SOURCE.get(current_role, []))


def filter_frontier_items_by_target_roles(
    state: AgentState,
    frontier_items: list[dict[str, object]],
    *,
    target_roles: set[str] | list[str],
) -> list[dict[str, object]]:
    role_order = {role: index for index, role in enumerate(list(target_roles))}
    selected: list[dict[str, object]] = []
    for item in frontier_items:
        if not isinstance(item, dict):
            continue
        item_role = str(item.get("page_role") or "").strip()
        item_url = str(item.get("url") or "").strip()
        if not item_role and item_url:
            item_role = classify_page_role(item_url)
        if item_role not in role_order:
            continue
        enriched_item = dict(item)
        enriched_item["page_role"] = item_role
        enriched_item["_target_role_rank"] = role_order[item_role]
        selected.append(enriched_item)
    selected.sort(
        key=lambda item: (
            coerce_rank(item.get("_target_role_rank")),
            -int(item.get("score", 0) or 0),
            -textual_fix_signal_score(item),
        )
    )
    if not selected:
        return []
    best_role_rank = coerce_rank(selected[0].get("_target_role_rank"))
    return [
        item
        for item in selected
        if coerce_rank(item.get("_target_role_rank")) == best_role_rank
    ]


def select_stage_guided_frontier_urls(
    state: AgentState,
    frontier_items: list[dict[str, object]],
) -> list[str]:
    target_roles = target_roles_for_current_stage(state)
    if not target_roles:
        return []
    prioritized_items = filter_frontier_items_by_target_roles(
        state,
        frontier_items,
        target_roles=target_roles,
    )
    if not prioritized_items:
        return []
    return select_fallback_frontier_urls(state, prioritized_items)


def build_rule_fallback_decision(state: AgentState) -> dict[str, object]:
    direct_candidates = list(state.get("direct_candidates", []))
    high_quality = [c for c in direct_candidates if candidate_priority(c) >= 90]
    low_quality = [c for c in direct_candidates if candidate_priority(c) < 90]

    if high_quality:
        return {
            "action": "try_candidate_download",
            "reason_summary": "规则回退：发现高质量 patch 候选（上游 commit），优先下载。",
            "selected_urls": [],
            "selected_candidate_keys": [
                str(candidate.get("canonical_key")) for candidate in high_quality
            ],
            "chain_updates": [],
            "new_chains": [],
        }

    frontier_items = unexpanded_frontier_items(state)
    fallback_urls = select_chain_guided_frontier_urls(state, frontier_items)
    if not fallback_urls:
        fallback_urls = select_stage_guided_frontier_urls(state, frontier_items)
    if not fallback_urls:
        fallback_urls = select_fallback_frontier_urls(state, frontier_items)
    if fallback_urls:
        return {
            "action": "expand_frontier",
            "reason_summary": (
                "规则回退：仅有低质量候选，按活跃链路继续探索寻找上游 commit。"
                if low_quality and select_chain_guided_frontier_urls(state, frontier_items)
                else (
                    "规则回退：仅有低质量候选，继续探索寻找上游 commit。"
                    if low_quality
                    else (
                        "规则回退：按活跃链路优先扩展期望角色 frontier。"
                        if select_chain_guided_frontier_urls(state, frontier_items)
                        else (
                            "规则回退：按当前链路阶段优先扩展目标角色 frontier。"
                            if select_stage_guided_frontier_urls(state, frontier_items)
                            else "规则回退：继续扩展未访问 frontier。"
                        )
                    )
                )
            ),
            "selected_urls": fallback_urls,
            "selected_candidate_keys": [],
            "chain_updates": [],
            "new_chains": [],
        }

    if low_quality:
        return {
            "action": "try_candidate_download",
            "reason_summary": "规则回退：无更多 frontier 可探索，下载现有低质量候选。",
            "selected_urls": [],
            "selected_candidate_keys": [
                str(candidate.get("canonical_key")) for candidate in low_quality
            ],
            "chain_updates": [],
            "new_chains": [],
        }

    return {
        "action": "stop_search",
        "reason_summary": "规则回退：没有可继续扩展的 frontier，也没有 patch 候选。",
        "selected_urls": [],
        "selected_candidate_keys": [],
        "chain_updates": [],
        "new_chains": [],
    }
