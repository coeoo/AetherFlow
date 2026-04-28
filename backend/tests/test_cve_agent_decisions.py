from __future__ import annotations

import json
from dataclasses import asdict

from app.config import load_settings
from app.cve.agent_state import build_initial_agent_state
from app.cve.browser.base import BrowserPageSnapshot
from app.cve.decisions import fallback
from app.cve.decisions import candidate_judge
from app.cve.decisions import navigation
from app.cve.decisions.fallback import build_rule_fallback_decision
from app.cve.decisions.fallback import select_fallback_frontier_urls


def _make_snapshot(
    url: str,
    *,
    page_role_hint: str = "frontier_page",
    title: str = "fake",
) -> BrowserPageSnapshot:
    return BrowserPageSnapshot(
        url=url,
        final_url=url,
        status_code=200,
        title=title,
        raw_html="<html><body>fake</body></html>",
        accessibility_tree="heading 'fake'",
        markdown_content="fake",
        links=[],
        page_role_hint=page_role_hint,
        fetch_duration_ms=100,
    )


def test_rule_fallback_prefers_direct_candidate_download() -> None:
    state = {
        "direct_candidates": [
            {
                "canonical_key": "commit-key",
                "patch_type": "github_commit_patch",
                "candidate_url": "https://github.com/acme/project/commit/abcdef1",
            }
        ],
        "frontier": [],
        "budget": {},
    }

    decision = build_rule_fallback_decision(state)

    assert decision["action"] == "try_candidate_download"
    assert decision["selected_candidate_keys"] == ["commit-key"]
    assert decision["selected_urls"] == []


def test_rule_fallback_explores_when_low_quality_candidate_has_frontier() -> None:
    state = {
        "direct_candidates": [
            {
                "canonical_key": "distro-key",
                "patch_type": "debdiff",
                "candidate_url": "https://bugs.debian.org/bugreport.cgi?bug=1;filename=fix.diff",
            }
        ],
        "frontier": [
            {
                "url": "https://git.example.org/project/commit/abcdef1",
                "expanded": False,
                "score": 30,
                "page_role": "commit_page",
            }
        ],
        "budget": {
            "max_children_per_node": 1,
            "max_cross_domain_expansions": 1,
        },
        "visited_urls": [],
        "browser_snapshots": {},
    }

    decision = build_rule_fallback_decision(state)

    assert decision["action"] == "expand_frontier"
    assert decision["selected_urls"] == ["https://git.example.org/project/commit/abcdef1"]
    assert decision["selected_candidate_keys"] == []
    assert decision["reason_summary"] == "规则回退：仅有低质量候选，继续探索寻找上游 commit。"


def test_chain_guided_fallback_prefers_active_chain_expected_roles() -> None:
    state = build_initial_agent_state(run_id="run-1", cve_id="CVE-2024-0001")
    state["current_page_url"] = "https://lists.example.org/post"
    state["budget"]["max_children_per_node"] = 1
    state["budget"]["max_cross_domain_expansions"] = 1
    state["navigation_chains"] = [
        {
            "chain_id": "chain-1",
            "status": "in_progress",
            "expected_next_roles": ["commit_page", "pull_request_page"],
        }
    ]
    state["frontier"] = [
        {
            "url": "https://lists.example.org/archive",
            "expanded": False,
            "score": 100,
            "page_role": "mailing_list_page",
        },
        {
            "url": "https://github.com/acme/project/commit/abcdef1",
            "expanded": False,
            "score": 10,
            "page_role": "commit_page",
        },
    ]

    decision = build_rule_fallback_decision(state)

    assert decision["action"] == "expand_frontier"
    assert decision["selected_urls"] == ["https://github.com/acme/project/commit/abcdef1"]
    assert decision["reason_summary"] == "规则回退：按活跃链路优先扩展期望角色 frontier。"


def test_stage_guided_fallback_uses_current_snapshot_role_before_url_role() -> None:
    current_url = "https://nvd.nist.gov/vuln/detail/CVE-2024-3094"
    state = build_initial_agent_state(run_id="run-1", cve_id="CVE-2024-3094")
    state["current_page_url"] = current_url
    state["browser_snapshots"] = {
        current_url: asdict(
            _make_snapshot(
                current_url,
                page_role_hint="tracker_page",
                title="CVE-2024-3094 tracker",
            )
        )
    }
    state["budget"]["max_children_per_node"] = 1
    state["budget"]["max_cross_domain_expansions"] = 1
    state["frontier"] = [
        {
            "url": "https://example.com/advisory",
            "expanded": False,
            "score": 200,
            "page_role": "advisory_page",
        },
        {
            "url": "https://github.com/acme/project/commit/abcdef1",
            "expanded": False,
            "score": 10,
            "page_role": "commit_page",
        },
    ]

    decision = build_rule_fallback_decision(state)

    assert decision["action"] == "expand_frontier"
    assert decision["selected_urls"] == ["https://github.com/acme/project/commit/abcdef1"]
    assert decision["reason_summary"] == "规则回退：按当前链路阶段优先扩展目标角色 frontier。"


def test_fallback_url_selection_respects_cross_domain_budget() -> None:
    state = build_initial_agent_state(run_id="run-1", cve_id="CVE-2024-0001")
    state["current_page_url"] = "https://tracker.example.org/CVE-2024-0001"
    state["budget"]["max_children_per_node"] = 2
    state["budget"]["max_cross_domain_expansions"] = 0

    selected_urls = select_fallback_frontier_urls(
        state,
        [
            {
                "url": "https://git.example.org/project/commit/abcdef1",
                "expanded": False,
                "score": 100,
                "page_role": "commit_page",
            },
        ],
    )

    assert selected_urls == []


def test_rule_fallback_stops_when_no_candidates_or_frontier() -> None:
    decision = build_rule_fallback_decision(
        {
            "direct_candidates": [],
            "frontier": [],
            "budget": {},
        }
    )

    assert decision["action"] == "stop_search"
    assert decision["reason_summary"] == "规则回退：没有可继续扩展的 frontier，也没有 patch 候选。"
    assert decision["selected_urls"] == []
    assert decision["selected_candidate_keys"] == []


def test_agent_nodes_keeps_private_fallback_decision_facade() -> None:
    from app.cve import agent_nodes

    assert agent_nodes._STAGE_FALLBACK_TARGET_ROLES_BY_SOURCE is (
        fallback.STAGE_FALLBACK_TARGET_ROLES_BY_SOURCE
    )
    assert agent_nodes._candidate_priority is fallback.candidate_priority
    assert agent_nodes._select_fallback_frontier_urls is (
        fallback.select_fallback_frontier_urls
    )
    assert agent_nodes._select_chain_guided_frontier_urls is (
        fallback.select_chain_guided_frontier_urls
    )
    assert agent_nodes._target_roles_for_current_stage is (
        fallback.target_roles_for_current_stage
    )
    assert agent_nodes._filter_frontier_items_by_target_roles is (
        fallback.filter_frontier_items_by_target_roles
    )
    assert agent_nodes._select_stage_guided_frontier_urls is (
        fallback.select_stage_guided_frontier_urls
    )
    assert agent_nodes._build_rule_fallback_decision is fallback.build_rule_fallback_decision


def test_navigation_decision_client_builds_context_and_calls_llm(monkeypatch) -> None:
    snapshot = _make_snapshot(
        "https://tracker.example.org/CVE-2024-0001",
        page_role_hint="tracker_page",
        title="CVE-2024-0001",
    )
    state = build_initial_agent_state(run_id="run-1", cve_id="CVE-2024-0001")
    llm_decision_log: list[dict[str, object]] = []
    calls: list[tuple[str, object]] = []

    class _FakePageView:
        url = snapshot.url

    class _FakeNavigationContext:
        cve_id = state["cve_id"]

    fake_page_view = _FakePageView()
    fake_navigation_context = _FakeNavigationContext()
    expected_decision = {
        "action": "expand_frontier",
        "reason_summary": "继续探索",
        "selected_urls": ["https://github.com/acme/project/commit/abcdef1"],
        "selected_candidate_keys": [],
        "chain_updates": [],
        "new_chains": [],
    }

    def _fake_build_page_view(
        received_snapshot,
        received_candidates,
        *,
        cve_id: str,
        frontier_candidates,
    ):
        calls.append(("build_page_view", received_snapshot))
        assert received_snapshot is snapshot
        assert received_candidates == [{"candidate_url": "https://example.org/fix.patch"}]
        assert cve_id == "CVE-2024-0001"
        assert frontier_candidates == [{"url": "https://github.com/acme/project/commit/abcdef1"}]
        return fake_page_view

    def _fake_build_navigation_context(received_state, page_view):
        calls.append(("build_context", page_view))
        assert received_state is state
        assert page_view is fake_page_view
        return fake_navigation_context

    def _fake_call_navigation(context, *, llm_decision_log=None):
        calls.append(("call_llm", context))
        assert context is fake_navigation_context
        assert llm_decision_log is llm_decision_log_ref
        return expected_decision

    llm_decision_log_ref = llm_decision_log
    monkeypatch.setattr(
        "app.cve.decisions.navigation.build_llm_page_view",
        _fake_build_page_view,
    )
    monkeypatch.setattr(
        "app.cve.decisions.navigation.build_navigation_context",
        _fake_build_navigation_context,
    )
    monkeypatch.setattr(
        "app.cve.decisions.navigation.call_browser_agent_navigation",
        _fake_call_navigation,
    )

    navigation_context, decision = navigation.request_navigation_decision(
        state,
        snapshot=snapshot,
        candidates=[{"candidate_url": "https://example.org/fix.patch"}],
        frontier_candidates=[{"url": "https://github.com/acme/project/commit/abcdef1"}],
        llm_decision_log=llm_decision_log,
    )

    assert navigation_context is fake_navigation_context
    assert decision is expected_decision
    assert calls == [
        ("build_page_view", snapshot),
        ("build_context", fake_page_view),
        ("call_llm", fake_navigation_context),
    ]


def test_candidate_judge_feature_flag_defaults_to_disabled(monkeypatch) -> None:
    monkeypatch.delenv("AETHERFLOW_CVE_CANDIDATE_JUDGE_ENABLED", raising=False)

    settings = load_settings()

    assert settings.cve_candidate_judge_enabled is False


def test_candidate_judge_feature_flag_can_be_enabled(monkeypatch) -> None:
    monkeypatch.setenv("AETHERFLOW_CVE_CANDIDATE_JUDGE_ENABLED", "true")

    settings = load_settings()

    assert settings.cve_candidate_judge_enabled is True


def test_candidate_judge_result_schema_contains_required_fields() -> None:
    result = candidate_judge.CandidateJudgeResult(
        candidate_key="commit-key",
        verdict="accept",
        confidence=0.91,
        reason_summary="候选指向上游修复 commit。",
        rejection_reason="",
    )

    payload = result.to_dict()

    assert set(payload) == {
        "candidate_key",
        "verdict",
        "confidence",
        "reason_summary",
        "rejection_reason",
    }


def test_candidate_judge_client_parses_structured_response(monkeypatch) -> None:
    state = build_initial_agent_state(run_id="run-1", cve_id="CVE-2024-0001")
    candidate = {
        "canonical_key": "commit-key",
        "candidate_url": "https://github.com/acme/project/commit/abcdef1",
        "patch_type": "github_commit_patch",
    }

    class _FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "candidate_key": "commit-key",
                                    "verdict": "accept",
                                    "confidence": 0.87,
                                    "reason_summary": "候选补丁直接修改受影响代码。",
                                    "rejection_reason": "",
                                }
                            )
                        }
                    }
                ]
            }

    captured_payloads: list[dict[str, object]] = []

    def _fake_post(*args, **kwargs):
        captured_payloads.append(dict(kwargs.get("json") or {}))
        return _FakeResponse()

    monkeypatch.setenv("LLM_BASE_URL", "https://llm.example.test/v1")
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setenv("LLM_DEFAULT_MODEL", "test-model")
    monkeypatch.setattr("app.cve.decisions.candidate_judge.http_client.post", _fake_post)

    result = candidate_judge.call_candidate_judge(
        candidate_judge.build_candidate_judge_context(state, candidate),
    )

    assert result.to_dict() == {
        "candidate_key": "commit-key",
        "verdict": "accept",
        "confidence": 0.87,
        "reason_summary": "候选补丁直接修改受影响代码。",
        "rejection_reason": "",
    }
    assert captured_payloads[0]["model"] == "test-model"


def test_candidate_judge_client_reports_non_json_provider_response(monkeypatch) -> None:
    state = build_initial_agent_state(run_id="run-1", cve_id="CVE-2024-0001")
    candidate = {
        "canonical_key": "commit-key",
        "candidate_url": "https://github.com/acme/project/commit/abcdef1",
        "patch_type": "github_commit_patch",
    }

    class _FakeResponse:
        status_code = 502
        headers = {"content-type": "text/html"}
        text = "<html>bad gateway</html>"

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            raise ValueError("not json")

    def _fake_post(*args, **kwargs):
        return _FakeResponse()

    monkeypatch.setenv("LLM_BASE_URL", "https://llm.example.test/v1")
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setenv("LLM_DEFAULT_MODEL", "test-model")
    monkeypatch.setattr("app.cve.decisions.candidate_judge.http_client.post", _fake_post)

    try:
        candidate_judge.call_candidate_judge(
            candidate_judge.build_candidate_judge_context(state, candidate),
        )
    except RuntimeError as exc:
        message = str(exc)
    else:
        raise AssertionError("expected RuntimeError")

    assert "candidate_judge_provider_non_json_response" in message
    assert "status=502" in message
    assert "content_type=text/html" in message
    assert "bad gateway" in message
    assert "test-key" not in message


def test_candidate_judge_selection_returns_only_accepted_candidate_keys(monkeypatch) -> None:
    state = build_initial_agent_state(run_id="run-1", cve_id="CVE-2024-3094")
    candidates = [
        {
            "canonical_key": "commit-key",
            "candidate_url": "https://github.com/example/repo/commit/abcdef1.patch",
            "patch_type": "github_commit_patch",
        },
        {
            "canonical_key": "cvss-noise",
            "candidate_url": "https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator",
            "patch_type": "patch",
        },
    ]

    def _fake_call_candidate_judge(context):
        candidate_key = str(context.candidate["canonical_key"])
        if candidate_key == "commit-key":
            return candidate_judge.CandidateJudgeResult(
                candidate_key=candidate_key,
                verdict="accept",
                confidence=0.92,
                reason_summary="可信上游 commit patch。",
                rejection_reason="",
            )
        return candidate_judge.CandidateJudgeResult(
            candidate_key=candidate_key,
            verdict="reject",
            confidence=0.95,
            reason_summary="CVSS 计算器不是补丁。",
            rejection_reason="cvss_noise",
        )

    monkeypatch.setattr(
        "app.cve.decisions.candidate_judge.call_candidate_judge",
        _fake_call_candidate_judge,
    )

    selection = candidate_judge.select_candidate_keys_with_judge(state, candidates)

    assert selection.selected_candidate_keys == ["commit-key"]
    assert [result.verdict for result in selection.results] == ["accept", "reject"]
