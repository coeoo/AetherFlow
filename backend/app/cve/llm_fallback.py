from __future__ import annotations

import json
from typing import Any

import httpx

from app.config import Settings

_ALLOWED_DECISIONS = {"select_candidate", "needs_human_review", "abstain"}
_ALLOWED_CONFIDENCE_BANDS = {"low", "medium", "high"}
_PROVIDER_NAME = "openai_compatible"


def maybe_run_cve_llm_fallback(
    settings: Settings,
    *,
    trigger_reason: str,
    cve_id: str,
    seed_references: list[str],
    snapshots: list[dict[str, object]],
    patch_candidates: list[dict[str, object]],
    patches: list[object],
) -> dict[str, object] | None:
    if not settings.cve_llm_fallback_enabled:
        return None

    candidate_items = _build_candidate_items(patch_candidates=patch_candidates, patches=patches)
    source_items = _build_source_items(seed_references=seed_references, snapshots=snapshots)
    audit_base = _build_audit_base(
        settings=settings,
        trigger_reason=trigger_reason,
        input_candidate_count=len(candidate_items),
        input_source_count=len(source_items),
    )
    if not settings.llm_base_url or not settings.llm_api_key or not settings.llm_default_model:
        return _build_skipped_summary(
            audit_base,
            skip_reason="missing_provider_config",
            reason_summary="LLM fallback 已开启，但缺少必需的模型配置，已跳过。",
        )

    prepared_input = _prepare_input(
        settings=settings,
        trigger_reason=trigger_reason,
        cve_id=cve_id,
        source_items=source_items,
        candidate_items=candidate_items,
        audit_base=audit_base,
    )
    if prepared_input is None:
        return _build_skipped_summary(
            audit_base,
            skip_reason="unknown_skip_reason",
            reason_summary="LLM fallback 因未知原因被跳过。",
        )
    if "skip_summary" in prepared_input:
        return prepared_input["skip_summary"]

    request_payload = prepared_input["request_payload"]
    candidate_key_to_url = prepared_input["candidate_key_to_url"]

    try:
        response_content = _invoke_provider(
            settings,
            request_payload=request_payload,
        )
    except httpx.TimeoutException:
        return {
            **audit_base,
            "llm_invocation_status": "timeout",
            "llm_reason_summary": "LLM fallback 调用超时，已回退到规则链原始结论。",
        }
    except Exception:
        return {
            **audit_base,
            "llm_invocation_status": "provider_error",
            "llm_reason_summary": "LLM fallback 调用失败，已回退到规则链原始结论。",
        }

    parsed = _parse_response_content(response_content)
    if parsed is None:
        return {
            **audit_base,
            "llm_invocation_status": "invalid_response",
            "llm_reason_summary": "LLM 返回了不合法的结构化结果，已忽略。",
        }

    validated = _validate_response(
        trigger_reason=trigger_reason,
        payload=parsed,
        candidate_key_to_url=candidate_key_to_url,
    )
    if validated is None:
        reason_summary = "LLM 返回了不合法的结构化结果，已忽略。"
        if parsed.get("decision") == "select_candidate":
            reason_summary = "LLM 返回了未知 candidate key，已忽略。"
        return {
            **audit_base,
            "llm_invocation_status": "invalid_response",
            "llm_reason_summary": reason_summary,
        }

    summary = {
        **audit_base,
        "llm_invocation_status": "succeeded",
        "llm_decision": validated["decision"],
        "llm_confidence_band": validated["confidence_band"],
        "llm_reason_summary": validated["reason_summary"],
    }
    if validated["selected_candidate_key"] is not None:
        summary["llm_selected_candidate_key"] = validated["selected_candidate_key"]
        summary["llm_selected_candidate_url"] = str(
            validated["selected_candidate_url"] or validated["selected_candidate_key"]
        )
    return summary


def _prepare_input(
    *,
    settings: Settings,
    trigger_reason: str,
    cve_id: str,
    source_items: list[dict[str, str]],
    candidate_items: list[dict[str, object]],
    audit_base: dict[str, object],
) -> dict[str, object] | None:
    if trigger_reason not in {"no_patch_candidates", "patch_download_failed"}:
        return {
            "skip_summary": _build_skipped_summary(
                audit_base,
                skip_reason="unsupported_trigger_reason",
                reason_summary="当前 fallback 触发原因不受支持，已跳过。",
            )
        }
    if not source_items:
        return {
            "skip_summary": _build_skipped_summary(
                audit_base,
                skip_reason="empty_sources",
                reason_summary="当前没有可供 LLM fallback 使用的来源，已跳过。",
            )
        }
    if _source_items_exceed_budget(
        source_items,
        max_sources=settings.cve_llm_fallback_max_sources,
        max_source_chars=settings.cve_llm_fallback_max_source_chars,
    ):
        return {
            "skip_summary": _build_skipped_summary(
                audit_base,
                skip_reason="source_budget_exceeded",
                reason_summary="来源数量或摘要长度超过 LLM fallback 预算，已跳过。",
            )
        }

    if trigger_reason == "patch_download_failed":
        if not candidate_items:
            return {
                "skip_summary": _build_skipped_summary(
                    audit_base,
                    skip_reason="missing_candidates",
                    reason_summary="当前没有可复核的 patch 候选，已跳过。",
                )
            }
        if len(candidate_items) > settings.cve_llm_fallback_max_candidates:
            return {
                "skip_summary": _build_skipped_summary(
                    audit_base,
                    skip_reason="candidate_budget_exceeded",
                    reason_summary="候选 patch 数量超过 LLM fallback 预算，已跳过。",
                )
            }
    else:
        candidate_items = []

    candidate_key_to_url = {
        str(candidate["canonical_candidate_key"]): str(candidate["candidate_url"])
        for candidate in candidate_items
    }
    request_payload = {
        "cve_id": cve_id,
        "trigger_reason": trigger_reason,
        "source_policy": {
            "rules_first": True,
            "can_generate_new_urls": False,
            "can_override_rule_success": False,
            "decision_scope": (
                ["needs_human_review", "abstain"]
                if trigger_reason == "no_patch_candidates"
                else ["select_candidate", "needs_human_review", "abstain"]
            ),
        },
        "sources": source_items,
        "candidates": candidate_items,
    }
    return {
        "request_payload": request_payload,
        "candidate_key_to_url": candidate_key_to_url,
    }


def _build_audit_base(
    *,
    settings: Settings,
    trigger_reason: str,
    input_candidate_count: int,
    input_source_count: int,
) -> dict[str, object]:
    return {
        "llm_fallback_triggered": True,
        "llm_trigger_reason": trigger_reason,
        "llm_model": settings.llm_default_model,
        "llm_provider": _PROVIDER_NAME,
        "llm_verdict_source": "llm_fallback",
        "llm_input_candidate_count": input_candidate_count,
        "llm_input_source_count": input_source_count,
    }


def _build_skipped_summary(
    audit_base: dict[str, object],
    *,
    skip_reason: str,
    reason_summary: str,
) -> dict[str, object]:
    return {
        **audit_base,
        "llm_invocation_status": "skipped",
        "llm_skip_reason": skip_reason,
        "llm_reason_summary": reason_summary,
    }


def _build_source_items(
    *,
    seed_references: list[str],
    snapshots: list[dict[str, object]],
) -> list[dict[str, str]]:
    source_items: list[dict[str, str]] = []
    for reference in seed_references:
        normalized_reference = reference.strip()
        if not normalized_reference:
            continue
        source_items.append(
            {
                "source_kind": "seed_reference",
                "url": normalized_reference,
            }
        )

    for snapshot in snapshots:
        source_url = str(snapshot.get("url") or "").strip()
        content_excerpt = _build_content_excerpt(str(snapshot.get("content") or ""))
        if not source_url and not content_excerpt:
            continue
        source_items.append(
            {
                "source_kind": "page_snapshot",
                "url": source_url,
                "content_excerpt": content_excerpt,
            }
        )

    return source_items


def _source_items_exceed_budget(
    source_items: list[dict[str, str]],
    *,
    max_sources: int,
    max_source_chars: int,
) -> bool:
    if len(source_items) > max_sources:
        return True
    source_char_total = sum(
        len(item.get("url", "")) + len(item.get("content_excerpt", ""))
        for item in source_items
    )
    return source_char_total > max_source_chars


def _build_candidate_items(
    *,
    patch_candidates: list[dict[str, object]],
    patches: list[object],
) -> list[dict[str, object]]:
    failure_by_candidate_url: dict[str, str] = {}
    for patch in patches:
        candidate_url = str(_patch_attr(patch, "candidate_url", default="") or "").strip()
        if not candidate_url:
            continue
        patch_meta = _patch_attr(patch, "patch_meta_json", default={}) or {}
        if not isinstance(patch_meta, dict):
            patch_meta = {}
        failure_by_candidate_url[candidate_url] = str(patch_meta.get("error") or "").strip()

    candidate_items: list[dict[str, object]] = []
    for candidate in patch_candidates:
        canonical_candidate_key = str(candidate.get("canonical_candidate_key") or "").strip()
        candidate_url = str(candidate.get("candidate_url") or "").strip()
        if not canonical_candidate_key or not candidate_url:
            continue
        candidate_items.append(
            {
                "canonical_candidate_key": canonical_candidate_key,
                "candidate_url": candidate_url,
                "patch_type": str(candidate.get("patch_type") or ""),
                "discovered_from_url": str(candidate.get("discovered_from_url") or ""),
                "discovered_from_host": str(candidate.get("discovered_from_host") or ""),
                "discovery_rule": str(candidate.get("discovery_rule") or ""),
                "evidence_source_count": int(candidate.get("evidence_source_count") or 0),
                "discovery_sources": candidate.get("discovery_sources") or [],
                "download_error": failure_by_candidate_url.get(candidate_url, ""),
            }
        )
    return candidate_items


def _build_content_excerpt(content: str) -> str:
    compact = " ".join(content.split())
    return compact[:280]


def _patch_attr(patch: object, attr_name: str, *, default: object) -> object:
    if isinstance(patch, dict):
        return patch.get(attr_name, default)
    return getattr(patch, attr_name, default)


def _invoke_provider(
    settings: Settings,
    *,
    request_payload: dict[str, object],
) -> str:
    response = httpx.post(
        _build_chat_completions_url(settings.llm_base_url),
        timeout=float(settings.llm_timeout_seconds),
        headers={
            "Authorization": f"Bearer {settings.llm_api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": settings.llm_default_model,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "你是受限的 CVE patch fallback 助手。"
                        "你只能基于提供的 sources 和 candidates 做结构化判断。"
                        "禁止生成新 URL，禁止编造未知 candidate key，"
                        "禁止覆盖规则链已经成功下载的 patch 结论。"
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        request_payload,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ),
                },
            ],
        },
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise ValueError("LLM 响应不是 JSON object")
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ValueError("LLM 响应缺少 choices")
    first_choice = choices[0]
    if not isinstance(first_choice, dict):
        raise ValueError("LLM 响应 choice 非法")
    message = first_choice.get("message")
    if not isinstance(message, dict):
        raise ValueError("LLM 响应缺少 message")
    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        raise ValueError("LLM 响应缺少 content")
    return content


def _build_chat_completions_url(base_url: str) -> str:
    normalized = base_url.rstrip("/")
    if normalized.endswith("/chat/completions"):
        return normalized
    return f"{normalized}/chat/completions"


def _parse_response_content(content: str) -> dict[str, object] | None:
    normalized = content.strip()
    if normalized.startswith("```"):
        normalized = normalized.strip("`")
        if normalized.startswith("json"):
            normalized = normalized[4:]
        normalized = normalized.strip()
    try:
        payload = json.loads(normalized)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _validate_response(
    *,
    trigger_reason: str,
    payload: dict[str, object],
    candidate_key_to_url: dict[str, str],
) -> dict[str, object] | None:
    decision = str(payload.get("decision") or "").strip()
    if decision not in _ALLOWED_DECISIONS:
        return None

    confidence_band = str(payload.get("confidence_band") or "").strip()
    if confidence_band not in _ALLOWED_CONFIDENCE_BANDS:
        return None

    reason_summary = str(payload.get("reason_summary") or "").strip()
    if not reason_summary:
        return None

    source_policy_ack = payload.get("source_policy_ack")
    if source_policy_ack is not True:
        return None

    selected_candidate_key = payload.get("selected_candidate_key")
    normalized_candidate_key = (
        str(selected_candidate_key).strip() if selected_candidate_key is not None else None
    )

    if trigger_reason == "no_patch_candidates" and decision == "select_candidate":
        return None

    if decision == "select_candidate":
        if not normalized_candidate_key or normalized_candidate_key not in candidate_key_to_url:
            return None
        return {
            "decision": decision,
            "selected_candidate_key": normalized_candidate_key,
            "selected_candidate_url": candidate_key_to_url[normalized_candidate_key],
            "confidence_band": confidence_band,
            "reason_summary": reason_summary,
        }

    return {
        "decision": decision,
        "selected_candidate_key": None,
        "selected_candidate_url": None,
        "confidence_band": confidence_band,
        "reason_summary": reason_summary,
    }
