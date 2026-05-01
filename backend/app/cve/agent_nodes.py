from __future__ import annotations

from dataclasses import asdict
import logging
from urllib.parse import urlparse
from uuid import UUID

from sqlalchemy import select

from app.config import load_settings
from app.cve.agent_evidence import append_decision_history
from app.cve.agent_evidence import build_budget_usage_summary
from app.cve.agent_evidence import build_candidate_record
from app.cve.agent_evidence import build_primary_family_summary
from app.cve.agent_evidence import count_page_roles
from app.cve.agent_evidence import ensure_search_node
from app.cve.agent_evidence import merge_candidate_into_state
from app.cve.agent_evidence import merge_evidence
from app.cve.agent_evidence import normalize_discovery_sources
from app.cve.agent_evidence import serialize_patch
from app.cve.agent_evidence import upsert_candidate_artifact
from app.cve.agent_evidence import upsert_page_node_state
from app.cve import agent_frontier_skill
from app.cve.agent_policy import count_consumed_pages
from app.cve.agent_policy import evaluate_stop_condition
from app.cve.agent_policy import unexpanded_frontier_items
from app.cve.agent_policy import validate_agent_decision
from app.cve.agent_policy import validate_needs_human_review
from app.cve.agent_state import AgentState
from app.cve.browser.base import BrowserPageSnapshot
from app.cve.browser.base import PageLink
from app.cve.browser.page_role_classifier import classify_page_role
from app.cve.candidate_generator import PatchCandidate, generate_candidates
from app.cve.canonical import canonicalize_candidate_url
from app.cve.chain_tracker import ChainTracker
from app.cve.decisions import candidate_judge as candidate_judge_decisions
from app.cve.decisions import fallback as fallback_decisions
from app.cve.decisions import navigation as navigation_decisions
from app.cve.frontier_planner import normalize_frontier_url, plan_frontier, score_frontier_url
from app.cve.page_analyzer import analyze_page
from app.cve.patch_downloader import download_patch_candidate
from app.cve.reference_matcher import get_candidate_priority
from app.cve.reference_matcher import match_reference_url
from app.cve import agent_search_tools
from app.cve.search_graph_service import (
    record_search_decision,
    record_search_edge,
    record_search_node,
)
from app.cve.seed_resolver import SeedReference, resolve_seed_enriched
from app.models import CVERun
from app.models.cve import CVECandidateArtifact, CVEPatchArtifact, CVESearchNode

_logger = logging.getLogger(__name__)

_GLOBAL_NOISE_PATH_FRAGMENTS = agent_search_tools.GLOBAL_NOISE_PATH_FRAGMENTS
_MAILING_LIST_NOISE_TEXTS = agent_search_tools.MAILING_LIST_NOISE_TEXTS
_MAILING_LIST_NOISE_PATH_FRAGMENTS = agent_search_tools.MAILING_LIST_NOISE_PATH_FRAGMENTS
_CVE_ID_RE = agent_search_tools.CVE_ID_RE
_extract_cve_ids = agent_search_tools.extract_cve_ids
_score_frontier_candidate = agent_search_tools.score_frontier_candidate
_is_navigation_noise_url = agent_search_tools.is_navigation_noise_url
_is_mailing_list_navigation_noise = agent_search_tools.is_mailing_list_navigation_noise
_is_high_value_frontier_link = agent_search_tools.is_high_value_frontier_link
_should_skip_frontier_link = agent_search_tools.should_skip_frontier_link
_filter_frontier_links = agent_search_tools.filter_frontier_links
_textual_fix_signal_score = agent_search_tools.textual_fix_signal_score
_coerce_rank = agent_search_tools.coerce_rank

_HIGH_PRIORITY_UPSTREAM_PATCH_TYPES = (
    agent_frontier_skill.HIGH_PRIORITY_UPSTREAM_PATCH_TYPES
)
_CODE_FIX_PAGE_ROLES = agent_frontier_skill.CODE_FIX_PAGE_ROLES
_target_cve_id = agent_frontier_skill.target_cve_id
_classify_tracker_page_relevance = agent_frontier_skill.classify_tracker_page_relevance
_should_keep_reference_link_in_frontier = (
    agent_frontier_skill.should_keep_reference_link_in_frontier
)
_filter_candidate_matches_for_page = (
    agent_frontier_skill.filter_candidate_matches_for_page
)
_build_frontier_candidate_records = agent_frontier_skill.build_frontier_candidate_records
_is_blocked_or_empty_page = agent_frontier_skill.is_blocked_or_empty_page

_STAGE_FALLBACK_TARGET_ROLES_BY_SOURCE = (
    fallback_decisions.STAGE_FALLBACK_TARGET_ROLES_BY_SOURCE
)
_candidate_priority = fallback_decisions.candidate_priority
_select_fallback_frontier_urls = fallback_decisions.select_fallback_frontier_urls
_select_chain_guided_frontier_urls = fallback_decisions.select_chain_guided_frontier_urls
_target_roles_for_current_stage = fallback_decisions.target_roles_for_current_stage
_filter_frontier_items_by_target_roles = (
    fallback_decisions.filter_frontier_items_by_target_roles
)
_select_stage_guided_frontier_urls = fallback_decisions.select_stage_guided_frontier_urls
_build_rule_fallback_decision = fallback_decisions.build_rule_fallback_decision
build_llm_page_view = navigation_decisions.build_navigation_page_view
build_navigation_context = navigation_decisions.build_agent_navigation_context
call_browser_agent_navigation = navigation_decisions.call_browser_agent_navigation
select_candidate_keys_with_judge = candidate_judge_decisions.select_candidate_keys_with_judge
_normalize_discovery_sources = normalize_discovery_sources
_build_candidate_record = build_candidate_record
_merge_evidence = merge_evidence
_merge_candidate_into_state = merge_candidate_into_state
_upsert_candidate_artifact = upsert_candidate_artifact
_upsert_page_node_state = upsert_page_node_state
_ensure_search_node = ensure_search_node
_append_decision_history = append_decision_history
_serialize_patch = serialize_patch
_build_primary_family_summary = build_primary_family_summary
_count_page_roles = count_page_roles
_build_budget_usage_summary = build_budget_usage_summary


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


def _apply_candidate_judge_to_download_decision(
    state: AgentState,
    *,
    session,
    run_id: UUID,
    node_id: UUID | None,
    selected_candidate_keys: list[str],
    reason_summary: str,
) -> tuple[list[str], str, str | None]:
    settings = load_settings()
    if not settings.cve_candidate_judge_enabled:
        return selected_candidate_keys, reason_summary, None

    direct_candidates = [
        dict(candidate)
        for candidate in list(state.get("direct_candidates") or [])
        if isinstance(candidate, dict)
    ]
    if selected_candidate_keys:
        selected_key_set = {str(key) for key in selected_candidate_keys}
        direct_candidates = [
            candidate
            for candidate in direct_candidates
            if str(candidate.get("canonical_key")) in selected_key_set
        ]
    if not direct_candidates:
        return selected_candidate_keys, reason_summary, None

    try:
        selection = select_candidate_keys_with_judge(state, direct_candidates)
    except Exception:
        _logger.warning("Candidate Judge 调用失败，保留原候选下载决策", exc_info=True)
        return selected_candidate_keys, reason_summary, None

    judge_results = selection.results
    rejection_reason = None
    if not judge_results:
        accepted_keys = []
        updated_reason_summary = "Candidate Judge 未返回可用候选判断。"
        rejection_reason = "candidate_judge_rejected_all"
    else:
        accepted_keys = list(selection.selected_candidate_keys)
        if accepted_keys:
            accepted_summaries = [
                result.reason_summary
                for result in judge_results
                if result.candidate_key in accepted_keys and result.reason_summary
            ]
            updated_reason_summary = (
                accepted_summaries[0] if accepted_summaries else "Candidate Judge 接受候选。"
            )
        else:
            rejection_summaries = [
                result.reason_summary
                for result in judge_results
                if result.reason_summary
            ]
            updated_reason_summary = (
                rejection_summaries[0]
                if rejection_summaries
                else "Candidate Judge 拒绝全部候选。"
            )
            rejection_reason = "candidate_judge_rejected_all"

    record_search_decision(
        session,
        run_id=run_id,
        node_id=node_id,
        decision_type="candidate_judge",
        input_payload={
            "candidate_keys": [
                str(candidate.get("canonical_key") or "")
                for candidate in direct_candidates
            ],
            "candidates": direct_candidates,
        },
        output_payload={
            "selected_candidate_keys": accepted_keys,
            "results": [result.to_dict() for result in judge_results],
        },
        validated=bool(accepted_keys),
        model_name=None,
        rejection_reason=rejection_reason,
        flush=True,
    )

    if accepted_keys:
        accepted_summaries = [
            result.reason_summary
            for result in judge_results
            if result.candidate_key in accepted_keys and result.reason_summary
        ]
        return (
            accepted_keys,
            updated_reason_summary,
            None,
        )

    return (
        [],
        updated_reason_summary,
        "candidate_judge_rejected_all",
    )


def _set_phase(run: CVERun, phase: str) -> None:
    run.status = "running"
    run.phase = phase


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


def resolve_seeds_node(state: AgentState) -> AgentState:
    session = _require_session(state)
    run = _require_run(session, run_id=state["run_id"])
    _set_phase(run, "resolve_seeds")
    session.flush()
    resolution = resolve_seed_enriched(session, run=run, cve_id=state["cve_id"])
    state["seed_references"] = resolution.references
    state["patch_evidence"] = resolution.evidence
    state["patch_candidates"] = resolution.candidates
    if not resolution.references:
        state["stop_reason"] = "no_seed_references"
    return state


def build_initial_frontier_node(state: AgentState) -> AgentState:
    session = _require_session(state)
    run = _require_run(session, run_id=state["run_id"])
    _set_phase(run, "build_initial_frontier")
    session.flush()

    run_id = UUID(state["run_id"])
    seed_references: list[SeedReference] = list(state.get("seed_references", []))
    patch_evidence_list = list(state.get("patch_evidence") or [])

    # seed_authority_by_url 来自 seed_references 的 normalized URL，用于 frontier 评分
    seed_authority_by_url: dict[str, int] = {}
    for reference in seed_references:
        normalized_reference = normalize_frontier_url(reference.url)
        if normalized_reference is None:
            continue
        seed_authority_by_url[normalized_reference] = max(
            seed_authority_by_url.get(normalized_reference, 0),
            int(reference.authority_score),
        )

    # 完整版：所有直接候选都经 candidate_generator 派生。
    # 每个 evidence 单独调 generator，让同 canonical_key 的多个 evidence 在
    # upsert_candidate_artifact 内部合并 evidence_source_count / discovery_sources。
    direct_candidates: list[dict[str, object]] = []
    seen_canonical_keys: set[str] = set()

    def _persist(pc: PatchCandidate, *, source_kind: str, snapshot_url: str) -> None:
        if not pc.downloadable:
            return
        bridge_dict: dict[str, str] = {
            "candidate_url": pc.candidate_url,
            "patch_type": pc.patch_type,
        }
        candidate_record = build_candidate_record(
            snapshot_url=snapshot_url,
            candidate=bridge_dict,
            source_kind=source_kind,
        )
        # PatchCandidate 已计算过 canonical_key（与 build_candidate_record 内部 canonicalize 等价），
        # 显式覆盖避免大小写或 query 顺序差异留痕。
        candidate_record["canonical_key"] = pc.canonical_key
        candidate_record["canonical_candidate_key"] = pc.canonical_key
        # 总是 upsert：DB 层按 (run_id, canonical_key) 合并 evidence_source_count / discovery_sources，
        # 多源发现统一计数。
        persisted = upsert_candidate_artifact(
            session,
            run_id=run_id,
            candidate_record=candidate_record,
            source_node_id=None,
        )
        candidate_record["evidence_source_count"] = int(
            persisted.evidence_json["evidence_source_count"]
        )
        candidate_record["discovery_sources"] = list(
            persisted.evidence_json["discovery_sources"]
        )
        if pc.canonical_key in seen_canonical_keys:
            # state["direct_candidates"] 同 canonical_key 记录已存在，仅刷新合并后的 evidence 字段
            for existing in direct_candidates:
                if existing.get("canonical_key") == pc.canonical_key:
                    existing["evidence_source_count"] = candidate_record["evidence_source_count"]
                    existing["discovery_sources"] = candidate_record["discovery_sources"]
                    break
            return
        seen_canonical_keys.add(pc.canonical_key)
        direct_candidates.append(candidate_record)

    for evidence in patch_evidence_list:
        # 完整版仅在 reference_url evidence 上接管 build_initial_frontier 的直接候选生成
        # （source_kind="seed"），与 baseline seed-derived 路径行为等价；
        # fix_commit evidence 派生的高置信候选留给 Phase C 显式 fast path 节点
        # （validate_seed_candidates）消费，避免在 Phase B+ 阶段引入 silent 短路。
        # 否则 fallback.py:287 的 >=90 阈值会让 fix_commit 多 host candidate 立即下载，
        # 破坏 ADR "现有 acceptance 场景结果不变" 的硬验收（CVE-2022-2509 fast-path 退化）。
        if evidence.evidence_type != "reference_url" or not evidence.url:
            continue
        source_kind = "seed"
        snapshot_url_for_record = normalize_frontier_url(evidence.url) or evidence.url
        for pc in generate_candidates([evidence]):
            _persist(pc, source_kind=source_kind, snapshot_url=snapshot_url_for_record)

    state["direct_candidates"] = direct_candidates

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

        node = ensure_search_node(session, run_id=run_id, frontier_item=frontier_item)
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
        upsert_page_node_state(state, node)
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
        if snapshot.page_role_hint in _CODE_FIX_PAGE_ROLES:
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
                    upsert_page_node_state(state, child_node)
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
            candidate_record = build_candidate_record(
                snapshot_url=snapshot.final_url or snapshot.url,
                candidate=candidate,
                source_kind="page",
            )
            persisted_candidate = upsert_candidate_artifact(
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
            merge_candidate_into_state(state, candidate_record)

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
        page_view = navigation_decisions.build_navigation_page_view(
            snapshot,
            list(current_observation.get("candidates") or []),
            cve_id=str(state.get("cve_id") or ""),
            frontier_candidates=list(current_observation.get("frontier_candidates") or []),
        )
        navigation_context = navigation_decisions.build_agent_navigation_context(
            state,
            page_view,
        )
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

    candidate_judge_stop_reason: str | None = None
    if action == "try_candidate_download":
        selected_candidate_keys, reason_summary, candidate_judge_stop_reason = (
            _apply_candidate_judge_to_download_decision(
                state,
                session=session,
                run_id=UUID(state["run_id"]),
                node_id=UUID(state["current_node_id"]) if state.get("current_node_id") else None,
                selected_candidate_keys=list(selected_candidate_keys),
                reason_summary=reason_summary,
            )
        )
        if candidate_judge_stop_reason is not None:
            action = "stop_search"
            selected_urls = []

    state["next_action"] = action
    state["selected_frontier_urls"] = selected_urls if action == "expand_frontier" else []
    state["selected_candidate_keys"] = (
        list(selected_candidate_keys) if action == "try_candidate_download" else []
    )
    if action == "stop_search":
        state["stop_reason"] = (
            candidate_judge_stop_reason
            or (evaluation.reason if evaluation.should_stop else "stop_search")
        )
    elif action == "needs_human_review":
        state["stop_reason"] = "needs_human_review"
    else:
        state["stop_reason"] = None

    append_decision_history(
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
    terminal_downloaded_count = sum(
        1 for candidate in persisted_candidates if candidate.download_status == "downloaded"
    )
    pending_candidates = [
        candidate
        for candidate in persisted_candidates
        if candidate.download_status not in {"downloaded", "failed"}
    ]
    if not pending_candidates:
        state["patches"] = []
        state["next_action"] = "finalize_run"
        state["stop_reason"] = (
            "patches_downloaded" if terminal_downloaded_count > 0 else "patch_download_failed"
        )
        session.flush()
        return state
    for candidate in pending_candidates:
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
        patches.append(serialize_patch(patch))
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
        "page_role_counts": count_page_roles(state),
        "pages_visited": count_consumed_pages(state),
        "cross_domain_hops": int(state.get("cross_domain_hops", 0)),
        "budget_usage": build_budget_usage_summary(state),
    }
    if downloaded_patches:
        summary["primary_patch_url"] = downloaded_patches[0].candidate_url
        summary.update(build_primary_family_summary(patches))
        run.status = "succeeded"
        run.stop_reason = str(state.get("stop_reason") or "patches_downloaded")
    else:
        run.status = "failed"
        run.stop_reason = str(state.get("stop_reason") or "no_patch_candidates")

    run.summary_json = summary
    session.flush()
    return state
