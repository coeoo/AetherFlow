from __future__ import annotations

from app.cve.agent_search_tools import extract_cve_ids
from app.cve.agent_search_tools import filter_frontier_links
from app.cve.agent_search_tools import score_frontier_candidate
from app.cve.agent_state import AgentState
from app.cve.browser.base import BrowserPageSnapshot
from app.cve.browser.base import PageLink
from app.cve.browser.page_role_classifier import classify_page_role
from app.cve.frontier_planner import normalize_frontier_url
from app.cve.reference_matcher import match_reference_url

HIGH_PRIORITY_UPSTREAM_PATCH_TYPES = {
    "github_commit_patch",
    "gitlab_commit_patch",
    "kernel_commit_patch",
    "github_pull_patch",
    "gitlab_merge_request_patch",
}
CODE_FIX_PAGE_ROLES = {
    "commit_page",
    "pull_request_page",
    "merge_request_page",
}


def target_cve_id(state: AgentState) -> str:
    return str(state.get("cve_id") or "").strip().upper()


def classify_tracker_page_relevance(
    snapshot: BrowserPageSnapshot,
    *,
    target_cve_id: str,
) -> str:
    if snapshot.page_role_hint != "tracker_page" or not target_cve_id:
        return "unknown"
    observed_cve_ids = extract_cve_ids(
        snapshot.final_url or snapshot.url,
        snapshot.title,
        snapshot.accessibility_tree,
        snapshot.markdown_content,
    )
    if not observed_cve_ids:
        return "unknown"
    if target_cve_id in observed_cve_ids:
        return "target"
    return "off_target"


def should_keep_reference_link_in_frontier(
    *,
    source_page_role: str,
    normalized_url: str,
    link: PageLink,
) -> bool:
    target_role = link.estimated_target_role or classify_page_role(normalized_url)
    return (
        source_page_role
        in {"tracker_page", "mailing_list_page", "bugtracker_page", "repository_page"}
        and target_role in CODE_FIX_PAGE_ROLES
    )


def filter_candidate_matches_for_page(
    state: AgentState,
    *,
    snapshot: BrowserPageSnapshot,
    candidate_matches: list[dict[str, str]],
) -> list[dict[str, str]]:
    if not candidate_matches:
        return []

    cve_id = target_cve_id(state)
    tracker_relevance = classify_tracker_page_relevance(
        snapshot,
        target_cve_id=cve_id,
    )
    filtered_candidates: list[dict[str, str]] = []
    for candidate in candidate_matches:
        patch_type = str(candidate.get("patch_type") or "")
        if snapshot.page_role_hint == "tracker_page":
            if tracker_relevance == "off_target":
                continue
            if patch_type in HIGH_PRIORITY_UPSTREAM_PATCH_TYPES:
                continue
        filtered_candidates.append(candidate)
    return filtered_candidates


def build_frontier_candidate_records(
    state: AgentState,
    *,
    snapshot: BrowserPageSnapshot,
    depth: int,
) -> list[dict[str, object]]:
    filtered_links = filter_frontier_links(snapshot.page_role_hint, snapshot.links)
    max_children_per_node = int(state["budget"].get("max_children_per_node", 5) or 5)
    cve_id = target_cve_id(state)
    tracker_relevance = classify_tracker_page_relevance(
        snapshot,
        target_cve_id=cve_id,
    )
    candidate_records_with_meta: list[tuple[dict[str, object], set[str]]] = []
    seen_urls: set[str] = set()
    for link in filtered_links:
        normalized_link = normalize_frontier_url(link.url)
        if normalized_link is None or normalized_link in seen_urls:
            continue
        matched_cve_ids = extract_cve_ids(normalized_link, link.text, link.context)
        if (
            snapshot.page_role_hint == "tracker_page"
            and tracker_relevance == "off_target"
            and cve_id
            and cve_id not in matched_cve_ids
        ):
            continue
        if (
            match_reference_url(normalized_link) is not None
            and not should_keep_reference_link_in_frontier(
                source_page_role=snapshot.page_role_hint,
                normalized_url=normalized_link,
                link=link,
            )
        ):
            continue
        seen_urls.add(normalized_link)
        candidate_records_with_meta.append(
            (
                {
                    "url": normalized_link,
                    "anchor_text": link.text,
                    "link_context": link.context,
                    "page_role": link.estimated_target_role
                    or classify_page_role(normalized_link),
                    "score": score_frontier_candidate(
                        normalized_url=normalized_link,
                        link=link,
                        target_cve_id=cve_id,
                        source_page_role=snapshot.page_role_hint,
                    ),
                    "depth": depth,
                },
                matched_cve_ids,
            )
        )
    if snapshot.page_role_hint == "tracker_page" and cve_id:
        has_target_tracker_link = any(
            record.get("page_role") == "tracker_page" and cve_id in matched_cve_ids
            for record, matched_cve_ids in candidate_records_with_meta
        )
        if has_target_tracker_link:
            candidate_records_with_meta = [
                (record, matched_cve_ids)
                for record, matched_cve_ids in candidate_records_with_meta
                if not (
                    record.get("page_role") == "tracker_page"
                    and matched_cve_ids
                    and cve_id not in matched_cve_ids
                )
            ]
    candidate_records = [record for record, _ in candidate_records_with_meta]
    candidate_records.sort(
        key=lambda item: int(item.get("score", 0) or 0),
        reverse=True,
    )
    return candidate_records[:max_children_per_node]


def is_blocked_or_empty_page(snapshot: BrowserPageSnapshot) -> bool:
    if str(snapshot.final_url or snapshot.url).startswith("chrome-error://"):
        return True
    normalized_markdown = " ".join(snapshot.markdown_content.lower().split())
    normalized_html = " ".join(snapshot.raw_html.lower().split())
    normalized_title = " ".join(snapshot.title.lower().split())
    if "unauthorized frame window" in normalized_markdown:
        return True
    if "unauthorized frame window" in normalized_html:
        return True
    if "requires javascript to be enabled" in normalized_markdown:
        return True
    if "requires javascript to be enabled" in normalized_html:
        return True
    if "checking connection, please wait" in normalized_markdown:
        return True
    if "checking connection, please wait" in normalized_html:
        return True
    if "i challenge thee" in normalized_title:
        return True
    if "just a moment" in normalized_title:
        return True
    if "checking your browser before accessing" in normalized_markdown:
        return True
    if "checking your browser before accessing" in normalized_html:
        return True
    return False
