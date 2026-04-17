import httpx

from app.cve.llm_fallback import maybe_run_cve_llm_fallback
from app.config import load_settings


def test_llm_fallback_marks_missing_provider_config_as_skipped(monkeypatch) -> None:
    monkeypatch.setenv("AETHERFLOW_CVE_LLM_FALLBACK_ENABLED", "true")
    monkeypatch.delenv("LLM_BASE_URL", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("LLM_DEFAULT_MODEL", raising=False)

    summary = maybe_run_cve_llm_fallback(
        load_settings(),
        trigger_reason="no_patch_candidates",
        cve_id="CVE-2024-3094",
        seed_references=["https://example.com/advisory"],
        snapshots=[
            {
                "url": "https://example.com/advisory",
                "content": "vendor advisory without patch",
            }
        ],
        patch_candidates=[],
        patches=[],
    )

    assert summary == {
        "llm_fallback_triggered": True,
        "llm_trigger_reason": "no_patch_candidates",
        "llm_invocation_status": "skipped",
        "llm_skip_reason": "missing_provider_config",
        "llm_reason_summary": "LLM fallback 已开启，但缺少必需的模型配置，已跳过。",
        "llm_model": "",
        "llm_provider": "openai_compatible",
        "llm_verdict_source": "llm_fallback",
        "llm_input_candidate_count": 0,
        "llm_input_source_count": 2,
    }


def test_llm_fallback_marks_candidate_budget_exceeded_as_skipped(monkeypatch) -> None:
    monkeypatch.setenv("AETHERFLOW_CVE_LLM_FALLBACK_ENABLED", "true")
    monkeypatch.setenv("AETHERFLOW_CVE_LLM_FALLBACK_MAX_CANDIDATES", "1")
    monkeypatch.setenv("LLM_BASE_URL", "https://llm.example.com/v1")
    monkeypatch.setenv("LLM_API_KEY", "demo-key")
    monkeypatch.setenv("LLM_DEFAULT_MODEL", "demo-model")

    summary = maybe_run_cve_llm_fallback(
        load_settings(),
        trigger_reason="patch_download_failed",
        cve_id="CVE-2024-3094",
        seed_references=["https://example.com/advisory"],
        snapshots=[],
        patch_candidates=[
            {
                "candidate_url": "https://example.com/fix-1.patch",
                "patch_type": "patch",
                "canonical_candidate_key": "https://example.com/fix-1.patch",
                "discovered_from_url": "https://example.com/advisory",
                "discovered_from_host": "example.com",
                "discovery_rule": "matcher",
                "discovery_sources": [],
                "evidence_source_count": 1,
            },
            {
                "candidate_url": "https://example.com/fix-2.patch",
                "patch_type": "patch",
                "canonical_candidate_key": "https://example.com/fix-2.patch",
                "discovered_from_url": "https://example.com/advisory",
                "discovered_from_host": "example.com",
                "discovery_rule": "matcher",
                "discovery_sources": [],
                "evidence_source_count": 1,
            },
        ],
        patches=[
            {
                "candidate_url": "https://example.com/fix-1.patch",
                "patch_meta_json": {"error": "403 forbidden"},
            },
            {
                "candidate_url": "https://example.com/fix-2.patch",
                "patch_meta_json": {"error": "404 not found"},
            },
        ],
    )

    assert summary == {
        "llm_fallback_triggered": True,
        "llm_trigger_reason": "patch_download_failed",
        "llm_invocation_status": "skipped",
        "llm_skip_reason": "candidate_budget_exceeded",
        "llm_reason_summary": "候选 patch 数量超过 LLM fallback 预算，已跳过。",
        "llm_model": "demo-model",
        "llm_provider": "openai_compatible",
        "llm_verdict_source": "llm_fallback",
        "llm_input_candidate_count": 2,
        "llm_input_source_count": 1,
    }


def test_llm_fallback_marks_source_budget_exceeded_as_skipped(monkeypatch) -> None:
    monkeypatch.setenv("AETHERFLOW_CVE_LLM_FALLBACK_ENABLED", "true")
    monkeypatch.setenv("AETHERFLOW_CVE_LLM_FALLBACK_MAX_SOURCES", "1")
    monkeypatch.setenv("LLM_BASE_URL", "https://llm.example.com/v1")
    monkeypatch.setenv("LLM_API_KEY", "demo-key")
    monkeypatch.setenv("LLM_DEFAULT_MODEL", "demo-model")

    summary = maybe_run_cve_llm_fallback(
        load_settings(),
        trigger_reason="no_patch_candidates",
        cve_id="CVE-2024-3094",
        seed_references=[
            "https://example.com/advisory",
            "https://example.com/blog",
        ],
        snapshots=[],
        patch_candidates=[],
        patches=[],
    )

    assert summary == {
        "llm_fallback_triggered": True,
        "llm_trigger_reason": "no_patch_candidates",
        "llm_invocation_status": "skipped",
        "llm_skip_reason": "source_budget_exceeded",
        "llm_reason_summary": "来源数量或摘要长度超过 LLM fallback 预算，已跳过。",
        "llm_model": "demo-model",
        "llm_provider": "openai_compatible",
        "llm_verdict_source": "llm_fallback",
        "llm_input_candidate_count": 0,
        "llm_input_source_count": 2,
    }


def test_llm_fallback_rejects_unknown_candidate_key(monkeypatch) -> None:
    monkeypatch.setenv("AETHERFLOW_CVE_LLM_FALLBACK_ENABLED", "true")
    monkeypatch.setenv("LLM_BASE_URL", "https://llm.example.com/v1")
    monkeypatch.setenv("LLM_API_KEY", "demo-key")
    monkeypatch.setenv("LLM_DEFAULT_MODEL", "demo-model")

    def _fake_http_post(url: str, **kwargs) -> httpx.Response:
        request = httpx.Request("POST", url)
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": (
                                '{"decision":"select_candidate","selected_candidate_key":"unknown-key",'
                                '"confidence_band":"low","reason_summary":"pick unknown",'
                                '"evidence_notes":["note"],"source_policy_ack":true}'
                            )
                        }
                    }
                ]
            },
            request=request,
        )

    monkeypatch.setattr("app.cve.llm_fallback.httpx.post", _fake_http_post)

    summary = maybe_run_cve_llm_fallback(
        load_settings(),
        trigger_reason="patch_download_failed",
        cve_id="CVE-2024-3094",
        seed_references=["https://example.com/advisory"],
        snapshots=[],
        patch_candidates=[
            {
                "candidate_url": "https://example.com/fix.patch",
                "patch_type": "patch",
                "canonical_candidate_key": "https://example.com/fix.patch",
                "discovered_from_url": "https://example.com/advisory",
                "discovered_from_host": "example.com",
                "discovery_rule": "matcher",
                "discovery_sources": [],
                "evidence_source_count": 1,
            }
        ],
        patches=[
            {
                "candidate_url": "https://example.com/fix.patch",
                "patch_meta_json": {"error": "403 forbidden"},
            }
        ],
    )

    assert summary == {
        "llm_fallback_triggered": True,
        "llm_trigger_reason": "patch_download_failed",
        "llm_invocation_status": "invalid_response",
        "llm_reason_summary": "LLM 返回了未知 candidate key，已忽略。",
        "llm_model": "demo-model",
        "llm_provider": "openai_compatible",
        "llm_verdict_source": "llm_fallback",
        "llm_input_candidate_count": 1,
        "llm_input_source_count": 1,
    }


def test_llm_fallback_rejects_invalid_structure(monkeypatch) -> None:
    monkeypatch.setenv("AETHERFLOW_CVE_LLM_FALLBACK_ENABLED", "true")
    monkeypatch.setenv("LLM_BASE_URL", "https://llm.example.com/v1")
    monkeypatch.setenv("LLM_API_KEY", "demo-key")
    monkeypatch.setenv("LLM_DEFAULT_MODEL", "demo-model")

    def _fake_http_post(url: str, **kwargs) -> httpx.Response:
        request = httpx.Request("POST", url)
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": (
                                '{"decision":"bad_decision","selected_candidate_key":null,'
                                '"confidence_band":"low","reason_summary":"bad",'
                                '"evidence_notes":["note"],"source_policy_ack":true}'
                            )
                        }
                    }
                ]
            },
            request=request,
        )

    monkeypatch.setattr("app.cve.llm_fallback.httpx.post", _fake_http_post)

    summary = maybe_run_cve_llm_fallback(
        load_settings(),
        trigger_reason="no_patch_candidates",
        cve_id="CVE-2024-3094",
        seed_references=["https://example.com/advisory"],
        snapshots=[
            {
                "url": "https://example.com/advisory",
                "content": "vendor advisory without patch",
            }
        ],
        patch_candidates=[],
        patches=[],
    )

    assert summary == {
        "llm_fallback_triggered": True,
        "llm_trigger_reason": "no_patch_candidates",
        "llm_invocation_status": "invalid_response",
        "llm_reason_summary": "LLM 返回了不合法的结构化结果，已忽略。",
        "llm_model": "demo-model",
        "llm_provider": "openai_compatible",
        "llm_verdict_source": "llm_fallback",
        "llm_input_candidate_count": 0,
        "llm_input_source_count": 2,
    }


def test_llm_fallback_timeout_does_not_break_baseline(monkeypatch) -> None:
    monkeypatch.setenv("AETHERFLOW_CVE_LLM_FALLBACK_ENABLED", "true")
    monkeypatch.setenv("LLM_BASE_URL", "https://llm.example.com/v1")
    monkeypatch.setenv("LLM_API_KEY", "demo-key")
    monkeypatch.setenv("LLM_DEFAULT_MODEL", "demo-model")

    def _raise_timeout(url: str, **kwargs):
        raise httpx.TimeoutException("request timeout")

    monkeypatch.setattr("app.cve.llm_fallback.httpx.post", _raise_timeout)

    summary = maybe_run_cve_llm_fallback(
        load_settings(),
        trigger_reason="patch_download_failed",
        cve_id="CVE-2024-3094",
        seed_references=["https://example.com/advisory"],
        snapshots=[],
        patch_candidates=[
            {
                "candidate_url": "https://example.com/fix.patch",
                "patch_type": "patch",
                "canonical_candidate_key": "https://example.com/fix.patch",
                "discovered_from_url": "https://example.com/advisory",
                "discovered_from_host": "example.com",
                "discovery_rule": "matcher",
                "discovery_sources": [],
                "evidence_source_count": 1,
            }
        ],
        patches=[
            {
                "candidate_url": "https://example.com/fix.patch",
                "patch_meta_json": {"error": "403 forbidden"},
            }
        ],
    )

    assert summary == {
        "llm_fallback_triggered": True,
        "llm_trigger_reason": "patch_download_failed",
        "llm_invocation_status": "timeout",
        "llm_reason_summary": "LLM fallback 调用超时，已回退到规则链原始结论。",
        "llm_model": "demo-model",
        "llm_provider": "openai_compatible",
        "llm_verdict_source": "llm_fallback",
        "llm_input_candidate_count": 1,
        "llm_input_source_count": 1,
    }


def test_llm_fallback_maps_selected_candidate_key_back_to_candidate_url(monkeypatch) -> None:
    monkeypatch.setenv("AETHERFLOW_CVE_LLM_FALLBACK_ENABLED", "true")
    monkeypatch.setenv("LLM_BASE_URL", "https://llm.example.com/v1")
    monkeypatch.setenv("LLM_API_KEY", "demo-key")
    monkeypatch.setenv("LLM_DEFAULT_MODEL", "demo-model")

    def _fake_http_post(url: str, **kwargs) -> httpx.Response:
        request = httpx.Request("POST", url)
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": (
                                '{"decision":"select_candidate",'
                                '"selected_candidate_key":"https://github.com/acme/project/commit/abc1234",'
                                '"confidence_band":"low","reason_summary":"pick commit patch",'
                                '"evidence_notes":["note"],"source_policy_ack":true}'
                            )
                        }
                    }
                ]
            },
            request=request,
        )

    monkeypatch.setattr("app.cve.llm_fallback.httpx.post", _fake_http_post)

    summary = maybe_run_cve_llm_fallback(
        load_settings(),
        trigger_reason="patch_download_failed",
        cve_id="CVE-2024-3094",
        seed_references=["https://example.com/advisory"],
        snapshots=[],
        patch_candidates=[
            {
                "candidate_url": "https://github.com/acme/project/commit/abc1234.patch",
                "patch_type": "github_commit_patch",
                "canonical_candidate_key": "https://github.com/acme/project/commit/abc1234",
                "discovered_from_url": "https://example.com/advisory",
                "discovered_from_host": "example.com",
                "discovery_rule": "matcher",
                "discovery_sources": [],
                "evidence_source_count": 1,
            }
        ],
        patches=[
            {
                "candidate_url": "https://github.com/acme/project/commit/abc1234.patch",
                "patch_meta_json": {"error": "403 forbidden"},
            }
        ],
    )

    assert summary == {
        "llm_fallback_triggered": True,
        "llm_trigger_reason": "patch_download_failed",
        "llm_invocation_status": "succeeded",
        "llm_decision": "select_candidate",
        "llm_selected_candidate_key": "https://github.com/acme/project/commit/abc1234",
        "llm_selected_candidate_url": "https://github.com/acme/project/commit/abc1234.patch",
        "llm_confidence_band": "low",
        "llm_reason_summary": "pick commit patch",
        "llm_model": "demo-model",
        "llm_provider": "openai_compatible",
        "llm_verdict_source": "llm_fallback",
        "llm_input_candidate_count": 1,
        "llm_input_source_count": 1,
    }
