from __future__ import annotations

from dataclasses import asdict
from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from app import http_client
from app.config import load_settings


_MAX_PROVIDER_BODY_PREVIEW_CHARS = 300
_REQUIRED_RESULT_FIELDS = {
    "candidate_key",
    "verdict",
    "confidence",
    "reason_summary",
    "rejection_reason",
}


@dataclass(frozen=True)
class CandidateJudgeContext:
    cve_id: str
    candidate: dict[str, object]
    discovered_candidates: list[dict[str, object]]
    navigation_chains: list[dict[str, object]]
    current_page_url: str


@dataclass(frozen=True)
class CandidateJudgeResult:
    candidate_key: str
    verdict: str
    confidence: float
    reason_summary: str
    rejection_reason: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class CandidateJudgeSelection:
    selected_candidate_keys: list[str]
    results: list[CandidateJudgeResult]

    def to_dict(self) -> dict[str, object]:
        return {
            "selected_candidate_keys": list(self.selected_candidate_keys),
            "results": [result.to_dict() for result in self.results],
        }


def build_candidate_judge_context(
    state: dict[str, object],
    candidate: dict[str, object],
) -> CandidateJudgeContext:
    return CandidateJudgeContext(
        cve_id=str(state.get("cve_id") or ""),
        candidate=dict(candidate),
        discovered_candidates=[
            dict(item)
            for item in list(state.get("direct_candidates") or [])
            if isinstance(item, dict)
        ],
        navigation_chains=[
            dict(item)
            for item in list(state.get("navigation_chains") or [])
            if isinstance(item, dict)
        ],
        current_page_url=str(state.get("current_page_url") or ""),
    )


def select_candidate_keys_with_judge(
    state: dict[str, object],
    candidates: list[dict[str, object]],
) -> CandidateJudgeSelection:
    selected_candidate_keys: list[str] = []
    results: list[CandidateJudgeResult] = []
    for candidate in candidates:
        canonical_key = str(
            candidate.get("canonical_key")
            or candidate.get("canonical_candidate_key")
            or ""
        ).strip()
        if not canonical_key:
            continue
        result = call_candidate_judge(build_candidate_judge_context(state, candidate))
        results.append(result)
        if result.verdict.strip().lower() != "accept":
            continue
        if result.candidate_key.strip() != canonical_key:
            continue
        selected_candidate_keys.append(canonical_key)
    return CandidateJudgeSelection(
        selected_candidate_keys=selected_candidate_keys,
        results=results,
    )


def _safe_response_body_preview(response: Any) -> str:
    text = str(getattr(response, "text", "") or "")
    text = text.replace("\r", "\\r").replace("\n", "\\n")
    if len(text) <= _MAX_PROVIDER_BODY_PREVIEW_CHARS:
        return text
    return text[:_MAX_PROVIDER_BODY_PREVIEW_CHARS] + "...<truncated>"


def _provider_response_context(response: Any) -> str:
    headers = getattr(response, "headers", {}) or {}
    content_type = ""
    if hasattr(headers, "get"):
        content_type = str(headers.get("content-type", "") or "")
    return (
        f"status={getattr(response, 'status_code', 'unknown')}, "
        f"content_type={content_type or 'unknown'}, "
        f"body_preview={_safe_response_body_preview(response)!r}"
    )


def call_candidate_judge(context: CandidateJudgeContext) -> CandidateJudgeResult:
    settings = load_settings()
    if not settings.llm_base_url or not settings.llm_api_key or not settings.llm_default_model:
        raise RuntimeError("missing_provider_config")

    response = http_client.post(
        f"{settings.llm_base_url.rstrip('/')}/chat/completions",
        timeout=float(settings.llm_timeout_seconds) if settings.llm_timeout_seconds > 0 else None,
        headers={
            "Authorization": f"Bearer {settings.llm_api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": settings.llm_default_model,
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "system",
                    "content": load_candidate_judge_prompt(),
                },
                {
                    "role": "user",
                    "content": json.dumps(asdict(context), ensure_ascii=False),
                },
            ],
        },
    )
    response.raise_for_status()
    try:
        payload = response.json()
    except ValueError as exc:
        raise RuntimeError(
            "candidate_judge_provider_non_json_response: "
            f"{_provider_response_context(response)}"
        ) from exc
    try:
        content = str(payload["choices"][0]["message"]["content"])
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError("candidate_judge provider 响应缺少 choices[0].message.content") from exc
    try:
        result_payload = json.loads(content)
    except json.JSONDecodeError as exc:
        content_preview = content.replace("\r", "\\r").replace("\n", "\\n")
        if len(content_preview) > _MAX_PROVIDER_BODY_PREVIEW_CHARS:
            content_preview = content_preview[:_MAX_PROVIDER_BODY_PREVIEW_CHARS] + "...<truncated>"
        raise ValueError(
            "candidate_judge message content 不是 JSON object: "
            f"content_preview={content_preview!r}"
        ) from exc
    if not isinstance(result_payload, dict):
        raise ValueError("candidate_judge 返回结果不是 JSON object")
    missing_fields = sorted(_REQUIRED_RESULT_FIELDS - set(result_payload))
    if missing_fields:
        raise ValueError(f"candidate_judge 缺少字段: {', '.join(missing_fields)}")
    return CandidateJudgeResult(
        candidate_key=str(result_payload["candidate_key"]),
        verdict=str(result_payload["verdict"]),
        confidence=float(result_payload["confidence"]),
        reason_summary=str(result_payload["reason_summary"]),
        rejection_reason=str(result_payload["rejection_reason"]),
    )


def load_candidate_judge_prompt() -> str:
    prompt_path = Path(__file__).resolve().parents[1] / "prompts" / "candidate_judge.md"
    return prompt_path.read_text(encoding="utf-8")
