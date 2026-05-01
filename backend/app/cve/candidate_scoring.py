"""多维候选评分模块 — 阶段 B 替代 CANDIDATE_PRIORITY 硬编码字典。

提供 MultiDimensionalScorer 统一评分接口，支持类型维度、来源维度、
发现强度维度和权威源维度的加权评分，所有权重可通过环境变量配置。
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlparse


# ── 补丁类型基础分数 ──────────────────────────────────────────

_PATCH_TYPE_BASE_SCORE: dict[str, int] = {
    "github_commit_patch": 100,
    "gitlab_commit_patch": 100,
    "kernel_commit_patch": 100,
    "bitbucket_commit_patch": 95,
    "gitee_commit_patch": 90,
    "github_pull_patch": 90,
    "gitlab_merge_request_patch": 90,
    "bitbucket_pull_patch": 85,
    "patch": 50,
    "diff": 50,
    "debdiff": 20,
    "bugzilla_attachment_patch": 40,
}

# ── 来源主机权重 ──────────────────────────────────────────────

_UPSTREAM_HOST_PATTERNS: dict[str, int] = {
    "github.com": 10,
    "gitlab.com": 10,
    "git.kernel.org": 10,
    "gitlab.freedesktop.org": 9,
    "gitlab.gnome.org": 9,
    "salsa.debian.org": 8,
    "bitbucket.org": 9,
    "gitee.com": 7,
    "android.googlesource.com": 8,
}

_DISTRIBUTION_HOST_PATTERNS: dict[str, int] = {
    "patches.ubuntu.com": -30,
    "bugs.debian.org": -30,
    "src.fedoraproject.org": -20,
    "download.suse.com": -20,
}

_DEFAULT_HOST_WEIGHT = 0


# ── 可配置权重 — 通过环境变量覆盖 ──────────────────────────────


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


@dataclass(frozen=True)
class ScorerWeights:
    type_weight: float = _env_float("AETHERFLOW_SCORING_TYPE_WEIGHT", 0.55)
    source_weight: float = _env_float("AETHERFLOW_SCORING_SOURCE_WEIGHT", 0.15)
    discovery_weight: float = _env_float("AETHERFLOW_SCORING_DISCOVERY_WEIGHT", 0.15)
    authority_weight: float = _env_float("AETHERFLOW_SCORING_AUTHORITY_WEIGHT", 0.15)


@dataclass(frozen=True)
class CandidateScore:
    """多维可解释评分结果。"""
    total: int
    type_score: int
    source_score: int
    discovery_score: int
    authority_score: int

    def to_dict(self) -> dict[str, int]:
        return {
            "total": self.total,
            "type_score": self.type_score,
            "source_score": self.source_score,
            "discovery_score": self.discovery_score,
            "authority_score": self.authority_score,
        }

    @staticmethod
    def low_quality_threshold() -> int:
        return int(os.getenv("AETHERFLOW_SCORING_LOW_QUALITY_THRESHOLD", "65"))


# ── 评分函数 ──────────────────────────────────────────────────


def _score_patch_type(patch_type: str) -> int:
    return _PATCH_TYPE_BASE_SCORE.get(patch_type, 50)


def _score_source_host(candidate_url: str) -> int:
    host = urlparse(candidate_url).netloc.lower()

    for pattern, weight in _DISTRIBUTION_HOST_PATTERNS.items():
        if pattern in host:
            return weight

    for pattern, weight in _UPSTREAM_HOST_PATTERNS.items():
        if pattern in host:
            return weight

    return _DEFAULT_HOST_WEIGHT


def _score_discovery_strength(discovery_count: int = 1) -> int:
    if discovery_count <= 0:
        discovery_count = 1
    if discovery_count >= 5:
        return 100
    if discovery_count >= 3:
        return 80
    if discovery_count >= 2:
        return 50
    return 20


def score_candidate(
    patch_type: str,
    candidate_url: str | None = None,
    *,
    discovery_count: int = 1,
    authority_score: int = 0,
    weights: ScorerWeights | None = None,
) -> CandidateScore:
    """计算候选补丁的多维评分。

    参数：
        patch_type: 补丁类型标识符（如 "github_commit_patch"）
        candidate_url: 候选 URL，用于来源主机判断
        discovery_count: 独立发现该候选的来源数量
        authority_score: 种子源权威分数（0-100）
        weights: 可选的权重覆盖
    """
    w = weights if weights is not None else ScorerWeights()
    url = candidate_url or ""

    type_score = min(100, _score_patch_type(patch_type))
    source_score = max(-30, min(30, _score_source_host(url)) + 30)
    discovery_score = _score_discovery_strength(discovery_count)
    authority_score_val = authority_score

    total = int(
        w.type_weight * type_score
        + w.source_weight * source_score
        + w.discovery_weight * discovery_score
        + w.authority_weight * authority_score_val
    )

    return CandidateScore(
        total=total,
        type_score=type_score,
        source_score=source_score,
        discovery_score=discovery_score,
        authority_score=authority_score_val,
    )


def get_candidate_priority(patch_type: str, candidate_url: str | None = None) -> int:
    """向后兼容的简化评分接口。

    返回 0-100 的整数评分，可直接替代 reference_matcher.get_candidate_priority。
    """
    score = score_candidate(patch_type, candidate_url)
    return score.total
