from __future__ import annotations

from dataclasses import asdict
import logging
import re
from urllib.parse import urlparse
from uuid import UUID

from sqlalchemy import select

from app.config import load_settings
from app.cve.agent_policy import count_consumed_pages
from app.cve.agent_policy import evaluate_stop_condition
from app.cve.agent_policy import unexpanded_frontier_items
from app.cve.agent_policy import validate_agent_decision
from app.cve.agent_policy import validate_needs_human_review
from app.cve.agent_state import AgentState
from app.cve.browser.base import BrowserPageSnapshot
from app.cve.browser.base import PageLink
from app.cve.browser.page_role_classifier import classify_page_role
from app.cve.browser_agent_llm import build_llm_page_view
from app.cve.browser_agent_llm import build_navigation_context
from app.cve.browser_agent_llm import call_browser_agent_navigation
from app.cve.canonical import canonicalize_candidate_url
from app.cve.chain_tracker import ChainTracker
from app.cve.frontier_planner import normalize_frontier_url, plan_frontier, score_frontier_url
from app.cve.page_analyzer import analyze_page
from app.cve.patch_downloader import download_patch_candidate
from app.cve.reference_matcher import get_candidate_priority
from app.cve.reference_matcher import match_reference_url
from app.cve.search_graph_service import (
    record_candidate_artifact,
    record_search_decision,
    record_search_edge,
    record_search_node,
)
from app.cve.seed_resolver import SeedReference, resolve_seed_references
from app.models import CVERun
from app.models.cve import CVECandidateArtifact, CVEPatchArtifact, CVESearchNode

_logger = logging.getLogger(__name__)

_GLOBAL_NOISE_PATH_FRAGMENTS = (
    "/login",
    "/signin",
    "/signup",
    "/register",
    "/msgid-search/",
    "/general",
    "/dashboard",
    "/about",
    "/contact",
    "/privacy",
    "/terms",
    "/help",
    "/features/",
    "/pricing",
    "/enterprise",
)
_MAILING_LIST_NOISE_TEXTS = {
    "date prev",
    "date next",
    "date index",
    "thread prev",
    "thread next",
    "author prev",
    "author next",
}
_MAILING_LIST_NOISE_PATH_FRAGMENTS = (
    "/maillist.html",
    "/threads.html",
    "/subject.html",
    "/author.html",
    "/date.html",
    "/prev-date.html",
    "/next-date.html",
    "/thrd",
)
_CVE_ID_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_HIGH_PRIORITY_UPSTREAM_PATCH_TYPES = {
    "github_commit_patch",
    "gitlab_commit_patch",
    "kernel_commit_patch",
    "github_pull_patch",
    "gitlab_merge_request_patch",
}


def _require_session(state: AgentState):
    session = state.get("session")
    if session is None:
        raise ValueError("Patch Agent state 缺少 session。")
    return session


def _require_run(session, *, run_id: str) -> CVERun:
    run = session.get(CVERun, UUID(run_id))
    if run is None:
        raise ValueError(f"CVE run 不存在: {run_id}")
    return run


def _require_browser_bridge(state: AgentState):
    bridge = state.get("_browser_bridge")
    if bridge is None:
        raise ValueError("Patch Agent state 缺少 _browser_bridge。")
    return bridge


def _set_phase(run: CVERun, phase: str) -> None:
    run.status = "running"
    run.phase = phase


def _normalize_discovery_sources(raw_sources: object) -> list[dict[str, object]]:
    if not isinstance(raw_sources, list):
        return []
    normalized_sources: list[dict[str, object]] = []
    for index, raw_source in enumerate(raw_sources):
        if not isinstance(raw_source, dict):
            continue
        source_url = str(
            raw_source.get("source_url")
            or raw_source.get("discovered_from_url")
            or ""
        ).strip()
        if not source_url:
            continue
        normalized_sources.append(
            {
                "source_url": source_url,
                "source_host": str(
                    raw_source.get("source_host") or urlparse(source_url).hostname or source_url
                ),
                "discovery_rule": str(raw_source.get("discovery_rule") or "matcher"),
                "source_kind": str(raw_source.get("source_kind") or "page"),
                "order": index,
            }
        )
    return normalized_sources


def _build_candidate_record(
    *,
    snapshot_url: str,
    candidate: dict[str, str],
    source_kind: str,
) -> dict[str, object]:
    canonical_key = canonicalize_candidate_url(candidate["candidate_url"])
    discovery_rule = (
        "bugzilla_attachment"
        if candidate.get("patch_type") == "bugzilla_attachment_patch"
        else "matcher"
    )
    source_host = urlparse(snapshot_url).hostname or snapshot_url
    return {
        "candidate_url": candidate["candidate_url"],
        "candidate_type": candidate["patch_type"],
        "patch_type": candidate["patch_type"],
        "canonical_key": canonical_key,
        "canonical_candidate_key": canonical_key,
        "discovered_from_url": snapshot_url,
        "discovered_from_host": source_host,
        "discovery_rule": discovery_rule,
        "discovery_sources": [
            {
                "source_url": snapshot_url,
                "source_host": source_host,
                "discovery_rule": discovery_rule,
                "source_kind": source_kind,
                "order": 0,
            }
        ],
        "evidence_source_count": 1,
    }


def _merge_evidence(
    *,
    existing: dict[str, object] | None,
    incoming: dict[str, object],
) -> dict[str, object]:
    merged_sources = _normalize_discovery_sources((existing or {}).get("discovery_sources"))
    seen_source_keys = {
        (
            str(source["source_url"]),
            str(source["discovery_rule"]),
            str(source["source_kind"]),
        )
        for source in merged_sources
    }
    for source in _normalize_discovery_sources(incoming.get("discovery_sources")):
        source_key = (
            str(source["source_url"]),
            str(source["discovery_rule"]),
            str(source["source_kind"]),
        )
        if source_key in seen_source_keys:
            continue
        merged_sources.append({**source, "order": len(merged_sources)})
        seen_source_keys.add(source_key)

    primary_source = merged_sources[0] if merged_sources else {
        "source_url": str(incoming.get("discovered_from_url") or incoming["candidate_url"]),
        "source_host": str(
            incoming.get("discovered_from_host")
            or urlparse(str(incoming.get("discovered_from_url") or incoming["candidate_url"])).hostname
            or incoming["candidate_url"]
        ),
        "discovery_rule": str(incoming.get("discovery_rule") or "matcher"),
        "source_kind": "page",
        "order": 0,
    }
    return {
        "source_kind": primary_source["source_kind"],
        "discovered_from_url": primary_source["source_url"],
        "discovery_sources": merged_sources or [primary_source],
        "evidence_source_count": len(merged_sources or [primary_source]),
    }


def _merge_candidate_into_state(state: AgentState, candidate_record: dict[str, object]) -> None:
    direct_candidates = list(state.get("direct_candidates", []))
    canonical_key = str(candidate_record["canonical_key"])
    for existing in direct_candidates:
        if str(existing.get("canonical_key")) != canonical_key:
            continue
        merged_evidence = _merge_evidence(existing=existing, incoming=candidate_record)
        existing.update(merged_evidence)
        existing["discovered_from_url"] = merged_evidence["discovered_from_url"]
        existing["evidence_source_count"] = merged_evidence["evidence_source_count"]
        state["direct_candidates"] = direct_candidates
        return
    direct_candidates.append(candidate_record)
    state["direct_candidates"] = direct_candidates


def _upsert_candidate_artifact(
    session,
    *,
    run_id: UUID,
    candidate_record: dict[str, object],
    source_node_id: UUID | None,
):
    statement = select(CVECandidateArtifact).where(
        CVECandidateArtifact.run_id == run_id,
        CVECandidateArtifact.canonical_key == str(candidate_record["canonical_key"]),
    )
    existing = session.execute(statement).scalar_one_or_none()
    merged_evidence = _merge_evidence(
        existing=dict(existing.evidence_json or {}) if existing is not None else None,
        incoming=candidate_record,
    )
    if existing is None:
        return record_candidate_artifact(
            session,
            run_id=run_id,
            candidate_url=str(candidate_record["candidate_url"]),
            candidate_type=str(candidate_record["candidate_type"]),
            canonical_key=str(candidate_record["canonical_key"]),
            download_status="discovered",
            validation_status="pending",
            source_node_id=source_node_id,
            evidence=merged_evidence,
            flush=True,
        )

    existing.evidence_json = merged_evidence
    if existing.source_node_id is None and source_node_id is not None:
        existing.source_node_id = source_node_id
    session.flush()
    return existing


def _upsert_page_node_state(state: AgentState, node: CVESearchNode) -> None:
    page_nodes = list(state.get("page_nodes", []))
    node_id = str(node.node_id)
    serialized = {
        "node_id": node_id,
        "url": node.url,
        "depth": node.depth,
        "host": node.host,
        "fetch_status": node.fetch_status,
        "page_role": node.page_role,
    }
    for item in page_nodes:
        if str(item.get("node_id")) == node_id:
            item.update(serialized)
            state["page_nodes"] = page_nodes
            return
    page_nodes.append(serialized)
    state["page_nodes"] = page_nodes


def _ensure_search_node(session, *, run_id: UUID, frontier_item: dict[str, object]) -> CVESearchNode:
    source_node_id = frontier_item.get("source_node_id")
    if source_node_id:
        node = session.get(CVESearchNode, UUID(str(source_node_id)))
        if node is not None:
            return node
    parsed = urlparse(str(frontier_item["url"]))
    node = record_search_node(
        session,
        run_id=run_id,
        url=str(frontier_item["url"]),
        depth=int(frontier_item.get("depth", 0)),
        host=parsed.hostname or parsed.netloc or str(frontier_item["url"]),
        page_role=str(frontier_item.get("page_role") or classify_page_role(str(frontier_item["url"]))),
        fetch_status=str(frontier_item.get("fetch_status") or "queued"),
        heuristic_features={"frontier_score": frontier_item.get("score", 0)},
        flush=True,
    )
    frontier_item["source_node_id"] = str(node.node_id)
    return node


def _find_frontier_item(
    state: AgentState,
    url: str,
    frontier_items: list[dict[str, object]] | None = None,
) -> dict[str, object] | None:
    search_items = frontier_items if frontier_items is not None else list(state.get("frontier", []))
    for item in search_items:
        if str(item.get("url")) == url:
            return item
    return None


def _append_decision_history(
    state: AgentState,
    *,
    decision_type: str,
    reason_summary: str,
    selected_urls: list[str],
    selected_candidate_keys: list[str],
    validated: bool,
    rejection_reason: str | None,
) -> None:
    decision_history = list(state.get("decision_history", []))
    decision_history.append(
        {
            "decision_type": decision_type,
            "reason_summary": reason_summary,
            "selected_urls": selected_urls,
            "selected_candidate_keys": selected_candidate_keys,
            "validated": validated,
            "rejection_reason": rejection_reason,
        }
    )
    state["decision_history"] = decision_history


def _serialize_patch(patch: CVEPatchArtifact) -> dict[str, object]:
    return {
        "patch_id": str(patch.patch_id),
        "candidate_url": patch.candidate_url,
        "patch_type": patch.patch_type,
        "download_status": patch.download_status,
        "patch_meta_json": dict(patch.patch_meta_json or {}),
    }


def _build_primary_family_summary(patches: list[CVEPatchArtifact]) -> dict[str, object]:
    if not patches:
        return {}
    grouped: dict[str, dict[str, object]] = {}
    order: list[str] = []
    for patch in patches:
        meta = dict(patch.patch_meta_json or {})
        source_url = str(meta.get("discovered_from_url") or patch.candidate_url)
        source_host = str(meta.get("discovered_from_host") or urlparse(source_url).hostname or source_url)
        family_key = f"family:{source_url}"
        if family_key not in grouped:
            order.append(family_key)
            grouped[family_key] = {
                "source_url": source_url,
                "source_host": source_host,
                "patch_count": 0,
                "downloaded_patch_count": 0,
                "related_source_hosts": [],
            }
        family = grouped[family_key]
        family["patch_count"] = int(family["patch_count"]) + 1
        if patch.download_status == "downloaded":
            family["downloaded_patch_count"] = int(family["downloaded_patch_count"]) + 1
        hosts = [
            str(source["source_host"])
            for source in _normalize_discovery_sources(meta.get("discovery_sources"))
        ]
        family["related_source_hosts"] = [
            host
            for host in [*list(family["related_source_hosts"]), *hosts]
            if host
        ]

    order_index = {key: idx for idx, key in enumerate(order)}
    primary_family = sorted(
        (grouped[key] for key in order),
        key=lambda family: (
            -int(family["downloaded_patch_count"]),
            -int(family["patch_count"]),
            order_index.get(f"family:{family['source_url']}", len(order)),
        ),
    )[0]
    dedup_hosts = list(dict.fromkeys(primary_family["related_source_hosts"]))[:3]
    return {
        "primary_family_source_url": primary_family["source_url"],
        "primary_family_source_host": primary_family["source_host"],
        "primary_family_evidence_source_count": len(
            list(dict.fromkeys(primary_family["related_source_hosts"]))
        ),
        "primary_family_related_source_hosts": dedup_hosts,
    }


def _deserialize_browser_snapshot(raw_snapshot: dict[str, object]) -> BrowserPageSnapshot:
    links = [
        PageLink(
            url=str(link.get("url") or ""),
            text=str(link.get("text") or ""),
            context=str(link.get("context") or ""),
            is_cross_domain=bool(link.get("is_cross_domain")),
            estimated_target_role=str(link.get("estimated_target_role") or ""),
        )
        for link in list(raw_snapshot.get("links") or [])
        if isinstance(link, dict)
    ]
    return BrowserPageSnapshot(
        url=str(raw_snapshot.get("url") or ""),
        final_url=str(raw_snapshot.get("final_url") or ""),
        status_code=int(raw_snapshot.get("status_code") or 0),
        title=str(raw_snapshot.get("title") or ""),
        raw_html=str(raw_snapshot.get("raw_html") or ""),
        accessibility_tree=str(raw_snapshot.get("accessibility_tree") or ""),
        markdown_content=str(raw_snapshot.get("markdown_content") or ""),
        links=links,
        page_role_hint=str(raw_snapshot.get("page_role_hint") or ""),
        fetch_duration_ms=int(raw_snapshot.get("fetch_duration_ms") or 0),
    )


def _load_chain_tracker(state: AgentState) -> ChainTracker:
    return ChainTracker.from_dict_list(list(state.get("navigation_chains", [])))


def _store_chain_tracker(state: AgentState, tracker: ChainTracker) -> None:
    state["navigation_chains"] = tracker.to_dict_list()


def _infer_chain_type(page_role: str) -> str:
    if page_role == "tracker_page":
        return "tracker_to_commit"
    if page_role == "mailing_list_page":
        return "mailing_list_to_fix"
    return "advisory_to_patch"


def _append_page_role_history(state: AgentState, *, url: str, role: str, title: str, depth: int) -> None:
    page_role_history = list(state.get("page_role_history", []))
    entry = {
        "url": url,
        "role": role,
        "title": title,
        "depth": str(depth),
    }
    if page_role_history and page_role_history[-1] == entry:
        return
    page_role_history.append(entry)
    state["page_role_history"] = page_role_history


def _extract_cve_ids(*values: str) -> set[str]:
    matched_ids: set[str] = set()
    for value in values:
        if not value:
            continue
        matched_ids.update(match.upper() for match in _CVE_ID_RE.findall(value))
    return matched_ids


def _target_cve_id(state: AgentState) -> str:
    return str(state.get("cve_id") or "").strip().upper()


def _classify_tracker_page_relevance(
    snapshot: BrowserPageSnapshot,
    *,
    target_cve_id: str,
) -> str:
    if snapshot.page_role_hint != "tracker_page" or not target_cve_id:
        return "unknown"
    observed_cve_ids = _extract_cve_ids(
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


def _score_frontier_candidate(
    *,
    normalized_url: str,
    link: PageLink,
    target_cve_id: str,
    source_page_role: str = "",
) -> int:
    target_role = link.estimated_target_role or classify_page_role(normalized_url)
    score = score_frontier_url(normalized_url)
    role_bonus = {
        "commit_page": 40,
        "download_page": 25,
        "tracker_page": 15,
        "bugtracker_page": 10,
    }
    score += role_bonus.get(target_role, 0)
    if source_page_role == "tracker_page":
        tracker_source_bonus = {
            "commit_page": 220,
            "download_page": 180,
            "tracker_page": 20,
            "bugtracker_page": -20,
            "advisory_page": -40,
        }
        score += tracker_source_bonus.get(target_role, 0)
    matched_cve_ids = _extract_cve_ids(normalized_url, link.text, link.context)
    if target_cve_id:
        if target_cve_id in matched_cve_ids:
            score += 120
        elif matched_cve_ids:
            score -= 160
    return score


def _should_keep_reference_link_in_frontier(
    *,
    source_page_role: str,
    normalized_url: str,
    link: PageLink,
) -> bool:
    target_role = link.estimated_target_role or classify_page_role(normalized_url)
    return source_page_role == "tracker_page" and target_role == "commit_page"


def _filter_candidate_matches_for_page(
    state: AgentState,
    *,
    snapshot: BrowserPageSnapshot,
    candidate_matches: list[dict[str, str]],
) -> list[dict[str, str]]:
    if not candidate_matches:
        return []

    target_cve_id = _target_cve_id(state)
    tracker_relevance = _classify_tracker_page_relevance(
        snapshot,
        target_cve_id=target_cve_id,
    )
    filtered_candidates: list[dict[str, str]] = []
    for candidate in candidate_matches:
        patch_type = str(candidate.get("patch_type") or "")
        if snapshot.page_role_hint == "tracker_page":
            if tracker_relevance == "off_target":
                continue
            if patch_type in _HIGH_PRIORITY_UPSTREAM_PATCH_TYPES:
                # tracker 页应先进入 commit/PR/MR 页面，再从源码托管页下载 patch，
                # 否则会在证据层绕过 commit_page。
                continue
        filtered_candidates.append(candidate)
    return filtered_candidates


def _is_navigation_noise_url(url: str) -> bool:
    normalized = url.lower()
    parsed = urlparse(normalized)
    if parsed.scheme in {"mailto", "javascript", "tel"}:
        return True
    if normalized in {
        "https://www.debian.org/security/",
        "https://www.debian.org/lts/security/",
        "https://www.debian.org/security/faq",
    }:
        return True
    path = parsed.path or "/"
    return any(fragment in path for fragment in _GLOBAL_NOISE_PATH_FRAGMENTS)


def _is_mailing_list_navigation_noise(link: PageLink) -> bool:
    normalized_text = " ".join(link.text.lower().split())
    normalized_context = " ".join(link.context.lower().split())
    normalized_url = link.url.lower()
    path = urlparse(normalized_url).path or "/"
    if normalized_text in _MAILING_LIST_NOISE_TEXTS:
        return True
    if "mail archive navigation" in normalized_context:
        return True
    if normalized_context.startswith("message-id:"):
        return True
    if normalized_context.startswith("to:") or normalized_context.startswith("from:"):
        return True
    if normalized_context.startswith("reply-to:") or normalized_context.startswith("mail-followup-to:"):
        return True
    if normalized_context.startswith("prev by date:") or normalized_context.startswith("next by date:"):
        return True
    if normalized_context.startswith("previous by thread:") or normalized_context.startswith("next by thread:"):
        return True
    return any(fragment in path for fragment in _MAILING_LIST_NOISE_PATH_FRAGMENTS)


def _is_high_value_frontier_link(link: PageLink) -> bool:
    target_url = (normalize_frontier_url(link.url) or link.url).lower()
    target_role = (link.estimated_target_role or classify_page_role(target_url)).strip()
    if "security-tracker.debian.org/tracker/" in target_url:
        return True
    if target_role in {"tracker_page", "commit_page", "download_page"}:
        if target_url in {
            "https://www.debian.org/security/",
            "https://www.debian.org/lts/security/",
            "https://www.debian.org/security/faq",
        }:
            return False
        return True
    return any(
        marker in target_url
        for marker in (
            "/commit/",
            "/merge_requests/",
            ".patch",
            ".diff",
            ".debdiff",
        )
    )


def _should_skip_frontier_link(source_page_role: str, link: PageLink) -> bool:
    normalized_url = normalize_frontier_url(link.url)
    if normalized_url is None:
        return True
    if _is_high_value_frontier_link(link):
        return False
    if _is_navigation_noise_url(normalized_url):
        return True
    if source_page_role == "mailing_list_page" and _is_mailing_list_navigation_noise(link):
        return True
    return False


def _filter_frontier_links(source_page_role: str, links: list[PageLink]) -> list[PageLink]:
    filtered_links: list[PageLink] = []
    seen_urls: set[str] = set()
    for link in links:
        normalized_url = normalize_frontier_url(link.url)
        if normalized_url is None or normalized_url in seen_urls:
            continue
        seen_urls.add(normalized_url)
        if _should_skip_frontier_link(source_page_role, link):
            continue
        filtered_links.append(link)
    return filtered_links


def _build_frontier_candidate_records(
    state: AgentState,
    *,
    snapshot: BrowserPageSnapshot,
    depth: int,
) -> list[dict[str, object]]:
    filtered_links = _filter_frontier_links(snapshot.page_role_hint, snapshot.links)
    max_children_per_node = int(state["budget"].get("max_children_per_node", 5) or 5)
    target_cve_id = _target_cve_id(state)
    tracker_relevance = _classify_tracker_page_relevance(
        snapshot,
        target_cve_id=target_cve_id,
    )
    candidate_records_with_meta: list[tuple[dict[str, object], set[str]]] = []
    seen_urls: set[str] = set()
    for link in filtered_links:
        normalized_link = normalize_frontier_url(link.url)
        if normalized_link is None or normalized_link in seen_urls:
            continue
        matched_cve_ids = _extract_cve_ids(normalized_link, link.text, link.context)
        if (
            snapshot.page_role_hint == "tracker_page"
            and tracker_relevance == "off_target"
            and target_cve_id
            and target_cve_id not in matched_cve_ids
        ):
            continue
        if (
            match_reference_url(normalized_link) is not None
            and not _should_keep_reference_link_in_frontier(
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
                    "page_role": link.estimated_target_role or classify_page_role(normalized_link),
                    "score": _score_frontier_candidate(
                        normalized_url=normalized_link,
                        link=link,
                        target_cve_id=target_cve_id,
                        source_page_role=snapshot.page_role_hint,
                    ),
                    "depth": depth,
                },
                matched_cve_ids,
            )
        )
    if snapshot.page_role_hint == "tracker_page" and target_cve_id:
        has_target_tracker_link = any(
            record.get("page_role") == "tracker_page" and target_cve_id in matched_cve_ids
            for record, matched_cve_ids in candidate_records_with_meta
        )
        if has_target_tracker_link:
            candidate_records_with_meta = [
                (record, matched_cve_ids)
                for record, matched_cve_ids in candidate_records_with_meta
                if not (
                    record.get("page_role") == "tracker_page"
                    and matched_cve_ids
                    and target_cve_id not in matched_cve_ids
                )
            ]
    candidate_records = [record for record, _ in candidate_records_with_meta]
    candidate_records.sort(key=lambda item: int(item.get("score", 0) or 0), reverse=True)
    return candidate_records[:max_children_per_node]


def _select_fallback_frontier_urls(
    state: AgentState,
    frontier_items: list[dict[str, object]],
) -> list[str]:
    current_page_url = str(state.get("current_page_url") or "").strip()
    current_host = urlparse(current_page_url).hostname or current_page_url
    current_page_role = classify_page_role(current_page_url) if current_page_url else ""
    visited_urls = {str(url) for url in state.get("visited_urls", [])}
    max_children = int(state["budget"].get("max_children_per_node", 1) or 1)
    remaining_cross_domain_budget = int(
        state["budget"].get("max_cross_domain_expansions", 0) or 0
    )

    same_domain_urls: list[tuple[int, str]] = []
    cross_domain_urls: list[tuple[int, str]] = []
    seen_urls: set[str] = set()

    for item in frontier_items:
        url = str(item.get("url") or "").strip()
        if not url or url in seen_urls or url in visited_urls:
            continue
        synthetic_link = PageLink(
            url=url,
            text=str(item.get("anchor_text") or ""),
            context=str(item.get("link_context") or ""),
            is_cross_domain=(urlparse(url).hostname or url) != current_host,
            estimated_target_role=str(item.get("page_role") or ""),
        )
        if _should_skip_frontier_link(current_page_role, synthetic_link):
            continue
        seen_urls.add(url)
        item_host = urlparse(url).hostname or url
        item_score = int(item.get("score", 0) or 0)
        if current_host and item_host == current_host:
            same_domain_urls.append((item_score, url))
        else:
            cross_domain_urls.append((item_score, url))

    same_domain_urls.sort(key=lambda item: item[0], reverse=True)
    cross_domain_urls.sort(key=lambda item: item[0], reverse=True)
    if cross_domain_urls and (
        not same_domain_urls or cross_domain_urls[0][0] > same_domain_urls[0][0]
    ):
        selected_urls = [
            url
            for _, url in cross_domain_urls[: min(max_children, remaining_cross_domain_budget)]
        ]
    else:
        selected_urls = [url for _, url in same_domain_urls[:max_children]]
    remaining_slots = max_children - len(selected_urls)
    if remaining_slots > 0 and remaining_cross_domain_budget > 0:
        selected_urls.extend(
            [
                url
                for _, url in cross_domain_urls[: min(remaining_slots, remaining_cross_domain_budget)]
                if url not in selected_urls
            ]
        )
    return selected_urls


def _candidate_priority(candidate: dict) -> int:
    """从候选 dict 获取质量优先级。"""
    patch_type = str(candidate.get("patch_type") or candidate.get("candidate_type") or "")
    candidate_url = str(candidate.get("candidate_url") or "")
    return get_candidate_priority(patch_type, candidate_url)


def _select_chain_guided_frontier_urls(
    state: AgentState,
    frontier_items: list[dict[str, object]],
) -> list[str]:
    active_chains = [
        chain
        for chain in list(state.get("navigation_chains") or [])
        if isinstance(chain, dict) and str(chain.get("status") or "") == "in_progress"
    ]
    expected_roles = {
        str(role).strip()
        for chain in active_chains
        for role in list(chain.get("expected_next_roles") or [])
        if str(role).strip()
    }
    if not expected_roles:
        return []

    prioritized_items = [
        item
        for item in frontier_items
        if isinstance(item, dict) and str(item.get("page_role") or "").strip() in expected_roles
    ]
    if not prioritized_items:
        return []
    return _select_fallback_frontier_urls(state, prioritized_items)


def _build_rule_fallback_decision(state: AgentState) -> dict[str, object]:
    direct_candidates = list(state.get("direct_candidates", []))
    high_quality = [c for c in direct_candidates if _candidate_priority(c) >= 90]
    low_quality = [c for c in direct_candidates if _candidate_priority(c) < 90]

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
    fallback_urls = _select_chain_guided_frontier_urls(state, frontier_items)
    if not fallback_urls:
        fallback_urls = _select_fallback_frontier_urls(state, frontier_items)
    if fallback_urls:
        return {
            "action": "expand_frontier",
            "reason_summary": (
                "规则回退：仅有低质量候选，按活跃链路继续探索寻找上游 commit。"
                if low_quality and _select_chain_guided_frontier_urls(state, frontier_items)
                else (
                    "规则回退：仅有低质量候选，继续探索寻找上游 commit。"
                    if low_quality
                    else (
                        "规则回退：按活跃链路优先扩展期望角色 frontier。"
                        if _select_chain_guided_frontier_urls(state, frontier_items)
                        else "规则回退：继续扩展未访问 frontier。"
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


def _apply_chain_updates(
    state: AgentState,
    *,
    tracker: ChainTracker,
    decision: dict[str, object],
    selected_urls: list[str],
    current_depth: int,
) -> None:
    selected_url_iter = iter(selected_urls)
    current_chain_id = str(state.get("current_chain_id") or "").strip()

    for raw_update in list(decision.get("chain_updates") or []):
        if not isinstance(raw_update, dict):
            continue
        chain_id = str(raw_update.get("chain_id") or current_chain_id).strip()
        if not chain_id:
            continue
        action = str(raw_update.get("action") or "").strip()
        if action == "extend":
            next_url = str(raw_update.get("url") or "").strip()
            if not next_url:
                next_url = next(selected_url_iter, "")
            if not next_url:
                continue
            next_role = str(raw_update.get("new_step_role") or classify_page_role(next_url))
            try:
                tracker.extend_chain(
                    chain_id,
                    url=next_url,
                    page_role=next_role,
                    depth=current_depth + 1,
                )
            except KeyError:
                continue
        elif action == "complete":
            try:
                tracker.complete_chain(chain_id)
            except KeyError:
                continue
        elif action == "mark_dead_end":
            try:
                tracker.mark_dead_end(chain_id)
            except KeyError:
                continue

    max_chains = int(state["budget"].get("max_chains", 5) or 5)
    for raw_chain in list(decision.get("new_chains") or []):
        if not isinstance(raw_chain, dict):
            continue
        chain_type = str(raw_chain.get("chain_type") or "").strip()
        initial_url = str(raw_chain.get("initial_url") or "").strip()
        page_role = str(raw_chain.get("page_role") or "").strip()
        if not chain_type or not initial_url or not page_role:
            continue
        try:
            tracker.create_chain(
                chain_type=chain_type,
                initial_url=initial_url,
                page_role=page_role,
                depth=current_depth,
                max_chains=max_chains,
            )
        except ValueError:
            break


def _count_page_roles(state: AgentState) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in list(state.get("page_role_history", [])):
        if not isinstance(item, dict):
            continue
        role = str(item.get("role") or "").strip()
        if not role:
            continue
        counts[role] = counts.get(role, 0) + 1
    return counts


def _build_budget_usage_summary(state: AgentState) -> dict[str, dict[str, int]]:
    budget = dict(state.get("budget") or {})
    initial_budget = dict(state.get("initial_budget") or {})
    cross_domain_used = int(state.get("cross_domain_hops", 0) or 0)
    cross_domain_remaining = int(budget.get("max_cross_domain_expansions", 0) or 0)
    cross_domain_max = int(
        initial_budget.get(
            "max_cross_domain_expansions",
            cross_domain_remaining + cross_domain_used,
        )
        or 0
    )
    return {
        "pages": {
            "used": count_consumed_pages(state),
            "max": int(budget.get("max_pages_total", 0) or 0),
        },
        "llm_calls": {
            "used": len(list(state.get("_llm_decision_log") or [])),
            "max": int(budget.get("max_llm_calls", 0) or 0),
        },
        "cross_domain": {
            "used": cross_domain_used,
            "max": max(cross_domain_max, cross_domain_used),
        },
    }


def _is_blocked_or_empty_page(snapshot: BrowserPageSnapshot) -> bool:
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


def resolve_seeds_node(state: AgentState) -> AgentState:
    session = _require_session(state)
    run = _require_run(session, run_id=state["run_id"])
    _set_phase(run, "resolve_seeds")
    session.flush()
    seed_references = resolve_seed_references(session, run=run, cve_id=state["cve_id"])
    state["seed_references"] = seed_references
    if not seed_references:
        state["stop_reason"] = "no_seed_references"
    return state


def build_initial_frontier_node(state: AgentState) -> AgentState:
    session = _require_session(state)
    run = _require_run(session, run_id=state["run_id"])
    _set_phase(run, "build_initial_frontier")
    session.flush()

    run_id = UUID(state["run_id"])
    seed_references: list[SeedReference] = list(state.get("seed_references", []))
    seed_authority_by_url: dict[str, int] = {}
    direct_candidates: list[dict[str, object]] = []
    for reference in seed_references:
        normalized_reference = normalize_frontier_url(reference.url)
        if normalized_reference is None:
            continue
        seed_authority_by_url[normalized_reference] = max(
            seed_authority_by_url.get(normalized_reference, 0),
            int(reference.authority_score),
        )
        matched_candidate = match_reference_url(normalized_reference)
        if matched_candidate is None:
            continue
        candidate_record = _build_candidate_record(
            snapshot_url=normalized_reference,
            candidate=matched_candidate,
            source_kind="seed",
        )
        persisted_candidate = _upsert_candidate_artifact(
            session,
            run_id=run_id,
            candidate_record=candidate_record,
            source_node_id=None,
        )
        candidate_record["evidence_source_count"] = int(
            persisted_candidate.evidence_json["evidence_source_count"]
        )
        candidate_record["discovery_sources"] = list(
            persisted_candidate.evidence_json["discovery_sources"]
        )
        direct_candidates.append(candidate_record)

    deduped_candidates: list[dict[str, object]] = []
    seen_candidate_keys: set[str] = set()
    for candidate in direct_candidates:
        canonical_key = str(candidate["canonical_key"])
        if canonical_key in seen_candidate_keys:
            continue
        seen_candidate_keys.add(canonical_key)
        deduped_candidates.append(candidate)
    state["direct_candidates"] = deduped_candidates

    tracker = _load_chain_tracker(state)
    frontier: list[dict[str, object]] = []
    for url in plan_frontier(seed_references):
        page_role = classify_page_role(url)
        chain_id = None
        try:
            chain = tracker.create_chain(
                chain_type=_infer_chain_type(page_role),
                initial_url=url,
                page_role=page_role,
                depth=0,
                max_chains=int(state["budget"].get("max_chains", 5) or 5),
            )
            chain_id = chain.chain_id
        except ValueError:
            chain_id = None
        frontier.append(
            {
                "url": url,
                "depth": 0,
                "score": score_frontier_url(
                    url,
                    authority_score=seed_authority_by_url.get(url, 0),
                ),
                "expanded": False,
                "fetch_status": "queued",
                "page_role": page_role,
                "chain_id": chain_id,
            }
        )
    state["frontier"] = frontier
    state["current_chain_id"] = frontier[0].get("chain_id") if frontier else None
    _store_chain_tracker(state, tracker)
    return state


def fetch_next_batch_node(state: AgentState) -> AgentState:
    session = _require_session(state)
    run = _require_run(session, run_id=state["run_id"])
    _set_phase(run, "fetch_next_batch")
    session.flush()

    if state.get("stop_reason") == "no_seed_references":
        return state

    remaining_budget = int(state["budget"].get("max_pages_total", 0)) - count_consumed_pages(state)
    if remaining_budget <= 0:
        state["stop_reason"] = "max_pages_total_exhausted"
        return state

    batch_limit = min(
        remaining_budget,
        int(state["budget"].get("max_parallel_frontier", 1) or 1),
    )
    selected_frontier_urls = {
        str(url)
        for url in state.get("selected_frontier_urls", [])
        if str(url).strip()
    }
    frontier_items = [
        item
        for item in state.get("frontier", [])
        if isinstance(item, dict) and not item.get("expanded")
    ]
    if selected_frontier_urls:
        frontier_items = [
            item for item in frontier_items if str(item.get("url")) in selected_frontier_urls
        ]

    bridge = _require_browser_bridge(state)
    settings = load_settings()
    page_observations = dict(state.get("page_observations", {}))
    browser_snapshots = dict(state.get("browser_snapshots", {}))
    visited_urls = list(state.get("visited_urls", []))
    run_id = UUID(state["run_id"])
    preferred_current_page_url: str | None = None
    preferred_current_node_id: str | None = None
    preferred_current_chain_id: str | None = None

    fetched_count = 0
    for frontier_item in frontier_items:
        if fetched_count >= batch_limit:
            break

        node = _ensure_search_node(session, run_id=run_id, frontier_item=frontier_item)
        try:
            snapshot = bridge.navigate(
                str(frontier_item["url"]),
                timeout_ms=settings.cve_browser_timeout_ms,
            )
            node.fetch_status = "fetched"
            node.page_role = snapshot.page_role_hint
            node.content_excerpt = snapshot.accessibility_tree[:400]
            frontier_item["fetch_status"] = "fetched"
            frontier_item["page_role"] = snapshot.page_role_hint
            browser_snapshots[str(frontier_item["url"])] = asdict(snapshot)
            observation = {
                "source_node_id": str(node.node_id),
                "url": snapshot.url,
                "depth": int(frontier_item.get("depth", 0)),
                "fetch_status": "fetched",
                "final_url": snapshot.final_url,
                "content_type": "text/html",
                "content": snapshot.raw_html,
                "extracted_links": [],
                "frontier_candidates": [],
                "candidates": [],
                "extracted": False,
                "title": snapshot.title,
                "page_role": snapshot.page_role_hint,
                "chain_id": frontier_item.get("chain_id"),
            }
            page_observations[str(frontier_item["url"])] = observation
            if not _is_blocked_or_empty_page(snapshot):
                preferred_current_page_url = str(frontier_item["url"])
                preferred_current_node_id = str(node.node_id)
                preferred_current_chain_id = frontier_item.get("chain_id")
            _append_page_role_history(
                state,
                url=snapshot.final_url or snapshot.url,
                role=snapshot.page_role_hint,
                title=snapshot.title,
                depth=int(frontier_item.get("depth", 0)),
            )
        except Exception as exc:
            node.fetch_status = "failed"
            node.content_excerpt = str(exc)
            frontier_item["fetch_status"] = "failed"
            observation = {
                "source_node_id": str(node.node_id),
                "url": str(frontier_item["url"]),
                "depth": int(frontier_item.get("depth", 0)),
                "fetch_status": "failed",
                "error": str(exc),
                "extracted_links": [],
                "frontier_candidates": [],
                "candidates": [],
                "extracted": True,
                "chain_id": frontier_item.get("chain_id"),
            }
            page_observations[str(frontier_item["url"])] = observation
        frontier_item["expanded"] = True
        frontier_item["source_node_id"] = str(node.node_id)
        _upsert_page_node_state(state, node)
        if str(frontier_item["url"]) not in visited_urls:
            visited_urls.append(str(frontier_item["url"]))
        fetched_count += 1

    state["page_observations"] = page_observations
    state["browser_snapshots"] = browser_snapshots
    state["visited_urls"] = visited_urls
    state["current_page_url"] = preferred_current_page_url
    state["current_node_id"] = preferred_current_node_id
    state["current_chain_id"] = preferred_current_chain_id
    state["selected_frontier_urls"] = []
    return state


def extract_links_and_candidates_node(state: AgentState) -> AgentState:
    session = _require_session(state)
    run = _require_run(session, run_id=state["run_id"])
    _set_phase(run, "extract_links_and_candidates")
    session.flush()

    if state.get("stop_reason") == "no_seed_references":
        return state

    run_id = UUID(state["run_id"])
    frontier = list(state.get("frontier", []))
    page_observations = dict(state.get("page_observations", {}))
    browser_snapshots = dict(state.get("browser_snapshots", {}))
    max_children_per_node = int(state["budget"].get("max_children_per_node", 5) or 5)

    for observation_key, observation in page_observations.items():
        if observation.get("fetch_status") != "fetched" or observation.get("extracted"):
            continue

        raw_snapshot = dict(browser_snapshots.get(observation_key) or {})
        if not raw_snapshot:
            continue
        snapshot = _deserialize_browser_snapshot(raw_snapshot)
        frontier_candidates = _build_frontier_candidate_records(
            state,
            snapshot=snapshot,
            depth=int(observation.get("depth", 0)) + 1,
        )
        extracted_links = [str(candidate["url"]) for candidate in frontier_candidates]
        candidate_matches: list[dict[str, str]] = list(
            analyze_page(
                {
                    "url": snapshot.final_url or snapshot.url,
                    "content": snapshot.raw_html,
                    "content_type": "text/html",
                }
            )
        )
        for link in snapshot.links:
            matched_candidate = match_reference_url(link.url)
            if matched_candidate is not None:
                candidate_matches.append(matched_candidate)
        if snapshot.page_role_hint == "commit_page":
            commit_candidate = match_reference_url(snapshot.final_url or snapshot.url)
            if commit_candidate is not None:
                candidate_matches.append(commit_candidate)
        candidate_matches = _filter_candidate_matches_for_page(
            state,
            snapshot=snapshot,
            candidate_matches=candidate_matches,
        )

        deduped_candidates: list[dict[str, str]] = []
        seen_candidate_keys: set[str] = set()
        for candidate in candidate_matches:
            canonical_key = canonicalize_candidate_url(candidate["candidate_url"])
            if canonical_key in seen_candidate_keys:
                continue
            seen_candidate_keys.add(canonical_key)
            deduped_candidates.append(candidate)

        observation["extracted_links"] = extracted_links
        observation["frontier_candidates"] = frontier_candidates
        observation["candidates"] = deduped_candidates
        observation["extracted"] = True
        page_observations[observation_key] = observation
        state["current_page_url"] = observation_key
        state["current_node_id"] = str(observation.get("source_node_id") or "")
        state["current_chain_id"] = observation.get("chain_id")

        source_node_id = observation.get("source_node_id")
        source_node_uuid = UUID(str(source_node_id)) if source_node_id else None
        if int(observation.get("depth", 0)) + 1 <= int(state["budget"].get("max_depth", 0) or 0):
            for candidate in frontier_candidates:
                normalized_link = str(candidate["url"])
                frontier_item = _find_frontier_item(state, normalized_link, frontier)
                if frontier_item is None:
                    child_node = record_search_node(
                        session,
                        run_id=run_id,
                        url=normalized_link,
                        depth=int(candidate["depth"]),
                        host=urlparse(normalized_link).hostname or normalized_link,
                        page_role=str(candidate.get("page_role") or classify_page_role(normalized_link)),
                        fetch_status="queued",
                        heuristic_features={"frontier_score": int(candidate.get("score", 0) or 0)},
                        flush=True,
                    )
                    frontier_item = {
                        "url": normalized_link,
                        "depth": int(candidate["depth"]),
                        "score": int(candidate.get("score", 0) or 0),
                        "expanded": False,
                        "fetch_status": "queued",
                        "source_node_id": str(child_node.node_id),
                        "chain_id": observation.get("chain_id"),
                        "page_role": str(candidate.get("page_role") or classify_page_role(normalized_link)),
                        "anchor_text": str(candidate.get("anchor_text") or ""),
                        "link_context": str(candidate.get("link_context") or ""),
                    }
                    frontier.append(frontier_item)
                    _upsert_page_node_state(state, child_node)
                if source_node_uuid is not None and frontier_item.get("source_node_id"):
                    record_search_edge(
                        session,
                        run_id=run_id,
                        from_node_id=source_node_uuid,
                        to_node_id=UUID(str(frontier_item["source_node_id"])),
                        edge_type=(
                            "follow_link_cross_domain"
                            if (urlparse(normalized_link).hostname or normalized_link)
                            != (urlparse(snapshot.final_url or snapshot.url).hostname or snapshot.final_url or snapshot.url)
                            else "follow_link"
                        ),
                        selected_by="browser",
                        anchor_text=str(candidate.get("anchor_text") or ""),
                        link_context=str(candidate.get("link_context") or ""),
                        flush=True,
                    )

        for candidate in deduped_candidates:
            candidate_record = _build_candidate_record(
                snapshot_url=snapshot.final_url or snapshot.url,
                candidate=candidate,
                source_kind="page",
            )
            persisted_candidate = _upsert_candidate_artifact(
                session,
                run_id=run_id,
                candidate_record=candidate_record,
                source_node_id=source_node_uuid,
            )
            candidate_record["evidence_source_count"] = int(
                persisted_candidate.evidence_json["evidence_source_count"]
            )
            candidate_record["discovery_sources"] = list(
                persisted_candidate.evidence_json["discovery_sources"]
            )
            _merge_candidate_into_state(state, candidate_record)

    state["frontier"] = frontier
    state["page_observations"] = page_observations
    return state


def agent_decide_node(state: AgentState) -> AgentState:
    session = _require_session(state)
    run = _require_run(session, run_id=state["run_id"])
    _set_phase(run, "agent_decide")
    session.flush()

    if state.get("stop_reason") == "no_seed_references":
        state["next_action"] = "finalize_run"
        state["selected_frontier_urls"] = []
        state["selected_candidate_keys"] = []
        return state

    state["iteration_count"] = int(state.get("iteration_count", 0)) + 1
    max_iterations = int(state["budget"].get("max_agent_iterations", 1) or 1)
    if int(state["iteration_count"]) > max_iterations:
        state["next_action"] = "stop_search"
        state["stop_reason"] = "max_agent_iterations_exhausted"
        return state

    current_page_url = str(state.get("current_page_url") or "").strip()
    browser_snapshots = dict(state.get("browser_snapshots") or {})
    raw_snapshot = dict(browser_snapshots.get(current_page_url) or {})
    current_observation = dict((state.get("page_observations") or {}).get(current_page_url) or {})
    decision: dict[str, object] | None = None
    selected_candidate_keys: list[str] = []
    selected_urls: list[str] = []
    reason_summary = "规则回退"
    navigation_context = None
    validation = None
    action = "stop_search"
    needs_rule_fallback = True
    model_name: str | None = None

    if raw_snapshot:
        snapshot = _deserialize_browser_snapshot(raw_snapshot)
        page_view = build_llm_page_view(
            snapshot,
            list(current_observation.get("candidates") or []),
            cve_id=str(state.get("cve_id") or ""),
            frontier_candidates=list(current_observation.get("frontier_candidates") or []),
        )
        navigation_context = build_navigation_context(state, page_view)
        max_llm_calls = int(state["budget"].get("max_llm_calls", 0) or 0)
        llm_call_count = len(list(state.get("_llm_decision_log") or []))
        if max_llm_calls > 0 and llm_call_count >= max_llm_calls:
            _logger.info(
                "LLM 决策预算已耗尽，跳过 LLM 调用并回退规则引擎: used=%d max=%d",
                llm_call_count,
                max_llm_calls,
            )
            reason_summary = "LLM 调用预算已耗尽，回退规则引擎。"
        else:
            try:
                decision = call_browser_agent_navigation(
                    navigation_context,
                    llm_decision_log=state.get("_llm_decision_log"),
                )
                selected_candidate_keys = [
                    str(key) for key in list(decision.get("selected_candidate_keys") or [])
                ]
                model_name = str(decision.get("model_name") or "") or None
                reason_summary = str(decision.get("reason_summary") or "LLM 导航决策")
                validation = validate_agent_decision(state, decision)
                record_search_decision(
                    session,
                    run_id=UUID(state["run_id"]),
                    node_id=UUID(state["current_node_id"]) if state.get("current_node_id") else None,
                    decision_type=str(decision.get("action") or "stop_search"),
                    input_payload=asdict(navigation_context),
                    output_payload={
                        "selected_urls": validation.normalized_selected_urls,
                        "selected_candidate_keys": selected_candidate_keys,
                    },
                    validated=validation.accepted,
                    model_name=model_name,
                    rejection_reason=validation.rejection_reason,
                    flush=True,
                )
                if validation.accepted:
                    normalized_action = validation.normalized_action
                    if normalized_action == "needs_human_review" and not validate_needs_human_review(
                        state
                    ):
                        selected_candidate_keys = []
                    else:
                        tracker = _load_chain_tracker(state)
                        _apply_chain_updates(
                            state,
                            tracker=tracker,
                            decision=decision,
                            selected_urls=validation.normalized_selected_urls,
                            current_depth=int(current_observation.get("depth", 0) or 0),
                        )
                        _store_chain_tracker(state, tracker)
                        action = normalized_action
                        selected_urls = list(validation.normalized_selected_urls)
                        needs_rule_fallback = False
                else:
                    selected_candidate_keys = []
            except Exception:
                _logger.warning("LLM 导航决策调用失败，回退到规则引擎", exc_info=True)
                selected_candidate_keys = []

    if needs_rule_fallback:
        decision = _build_rule_fallback_decision(state)
        selected_candidate_keys = [
            str(key) for key in list(decision.get("selected_candidate_keys") or [])
        ]
        reason_summary = str(decision.get("reason_summary") or "规则回退")
        validation = validate_agent_decision(state, decision)
        record_search_decision(
            session,
            run_id=UUID(state["run_id"]),
            node_id=UUID(state["current_node_id"]) if state.get("current_node_id") else None,
            decision_type="rule_fallback",
            input_payload={
                "current_page": (
                    asdict(navigation_context.current_page)
                    if navigation_context is not None
                    else {}
                ),
                "navigation_path": (
                    list(navigation_context.navigation_path)
                    if navigation_context is not None
                    else []
                ),
                "active_chains": (
                    list(navigation_context.active_chains)
                    if navigation_context is not None
                    else []
                ),
                "frontier_count": len(state.get("frontier", [])),
                "direct_candidate_count": len(state.get("direct_candidates", [])),
                "current_page_url": current_page_url,
            },
            output_payload={
                "action": decision["action"],
                "selected_urls": validation.normalized_selected_urls,
                "selected_candidate_keys": selected_candidate_keys,
            },
            validated=validation.accepted,
            model_name=None,
            rejection_reason=validation.rejection_reason,
            flush=True,
        )
        if validation.accepted:
            action = validation.normalized_action
            selected_urls = list(validation.normalized_selected_urls)
        else:
            action = "stop_search"
            selected_urls = []
            selected_candidate_keys = []

    evaluation = evaluate_stop_condition(state)
    if action == "stop_search" and not evaluation.should_stop:
        fallback_urls = _select_fallback_frontier_urls(state, unexpanded_frontier_items(state))
        if fallback_urls:
            action = "expand_frontier"
            selected_urls = fallback_urls
            reason_summary = "仍有活跃链路或 frontier，覆盖 stop_search 继续探索。"
        elif state.get("direct_candidates"):
            action = "try_candidate_download"
            selected_candidate_keys = []
            selected_urls = []
            reason_summary = "仍有候选可校验，覆盖 stop_search 继续下载。"

    state["next_action"] = action
    state["selected_frontier_urls"] = selected_urls if action == "expand_frontier" else []
    state["selected_candidate_keys"] = (
        list(selected_candidate_keys) if action == "try_candidate_download" else []
    )
    if action == "stop_search":
        state["stop_reason"] = evaluation.reason if evaluation.should_stop else "stop_search"
    elif action == "needs_human_review":
        state["stop_reason"] = "needs_human_review"
    else:
        state["stop_reason"] = None

    _append_decision_history(
        state,
        decision_type=action,
        reason_summary=reason_summary,
        selected_urls=list(selected_urls),
        selected_candidate_keys=selected_candidate_keys,
        validated=action != "stop_search" or evaluation.should_stop or bool(selected_urls),
        rejection_reason=None,
    )
    return state


def download_and_validate_node(state: AgentState) -> AgentState:
    session = _require_session(state)
    run = _require_run(session, run_id=state["run_id"])
    _set_phase(run, "download_and_validate")
    session.flush()

    download_attempt_limit = int(state["budget"].get("max_download_attempts", 1) or 1)
    persisted_candidates = session.execute(
        select(CVECandidateArtifact)
        .where(CVECandidateArtifact.run_id == UUID(state["run_id"]))
        .order_by(CVECandidateArtifact.created_at, CVECandidateArtifact.candidate_id)
    ).scalars().all()
    selected_candidate_keys = [
        str(key).strip()
        for key in list(state.get("selected_candidate_keys") or [])
        if str(key).strip()
    ]
    if selected_candidate_keys:
        selected_key_order = {
            canonical_key: index for index, canonical_key in enumerate(selected_candidate_keys)
        }
        filtered_candidates = [
            candidate
            for candidate in persisted_candidates
            if str(candidate.canonical_key) in selected_key_order
        ]
        if filtered_candidates:
            persisted_candidates = sorted(
                filtered_candidates,
                key=lambda candidate: selected_key_order[str(candidate.canonical_key)],
            )
    else:
        persisted_candidates = sorted(
            persisted_candidates,
            key=lambda candidate: get_candidate_priority(
                candidate.candidate_type,
                candidate.candidate_url,
            ),
            reverse=True,
        )

    patches: list[dict[str, object]] = []
    downloaded_count = 0
    attempted_count = 0
    for candidate in persisted_candidates:
        if attempted_count >= download_attempt_limit:
            break
        evidence = dict(candidate.evidence_json or {})
        patch = download_patch_candidate(
            session,
            run=run,
            candidate={
                "candidate_url": candidate.candidate_url,
                "patch_type": candidate.candidate_type,
                "canonical_candidate_key": candidate.canonical_key,
                "discovered_from_url": evidence.get("discovered_from_url"),
                "discovered_from_host": urlparse(
                    str(evidence.get("discovered_from_url") or candidate.candidate_url)
                ).hostname
                or str(evidence.get("discovered_from_url") or candidate.candidate_url),
                "discovery_rule": "matcher",
                "discovery_sources": evidence.get("discovery_sources"),
                "evidence_source_count": evidence.get("evidence_source_count"),
            },
        )
        patches.append(_serialize_patch(patch))
        candidate.download_status = patch.download_status
        candidate.validation_status = "validated" if patch.download_status == "downloaded" else "failed"
        candidate.artifact_id = patch.artifact_id
        if patch.download_status == "downloaded":
            downloaded_count += 1
        attempted_count += 1

    tracker = _load_chain_tracker(state)
    current_chain_id = str(state.get("current_chain_id") or "").strip()
    if downloaded_count > 0:
        if current_chain_id:
            try:
                tracker.complete_chain(current_chain_id)
            except KeyError:
                pass
        for remaining_chain in tracker.get_active_chains():
            remaining_id = remaining_chain.chain_id
            if remaining_id and remaining_id != current_chain_id:
                try:
                    tracker.complete_chain(remaining_id)
                except KeyError:
                    pass
    _store_chain_tracker(state, tracker)

    state["patches"] = patches
    evaluation = evaluate_stop_condition(state)
    if not evaluation.should_stop:
        state["next_action"] = "fetch_next_batch"
        state["stop_reason"] = None
    else:
        state["next_action"] = "finalize_run"
        if downloaded_count > 0:
            state["stop_reason"] = "patches_downloaded"
        elif persisted_candidates:
            state["stop_reason"] = "patch_download_failed"
        else:
            state["stop_reason"] = evaluation.reason
    session.flush()
    return state


def finalize_run_node(state: AgentState) -> AgentState:
    session = _require_session(state)
    run = _require_run(session, run_id=state["run_id"])
    run.phase = "finalize_run"

    patches = session.execute(
        select(CVEPatchArtifact)
        .where(CVEPatchArtifact.run_id == UUID(state["run_id"]))
        .order_by(CVEPatchArtifact.created_at, CVEPatchArtifact.patch_id)
    ).scalars().all()
    downloaded_patches = [patch for patch in patches if patch.download_status == "downloaded"]

    chain_tracker = _load_chain_tracker(state)
    summary = {
        "runtime_kind": "patch_agent_graph",
        "patch_found": bool(downloaded_patches),
        "patch_count": len(downloaded_patches),
        "chain_summary": chain_tracker.to_dict_list(),
        "page_role_counts": _count_page_roles(state),
        "pages_visited": count_consumed_pages(state),
        "cross_domain_hops": int(state.get("cross_domain_hops", 0)),
        "budget_usage": _build_budget_usage_summary(state),
    }
    if downloaded_patches:
        summary["primary_patch_url"] = downloaded_patches[0].candidate_url
        summary.update(_build_primary_family_summary(patches))
        run.status = "succeeded"
        run.stop_reason = str(state.get("stop_reason") or "patches_downloaded")
    else:
        run.status = "failed"
        run.stop_reason = str(state.get("stop_reason") or "no_patch_candidates")

    run.summary_json = summary
    session.flush()
    return state
