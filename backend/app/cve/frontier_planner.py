from __future__ import annotations

import re
from urllib.parse import urldefrag

from app.cve.reference_matcher import match_reference_url


MAX_FRONTIER_PAGES = 10
FRONTIER_PRIORITY_RULES: tuple[tuple[str, int], ...] = (
    ("security-tracker.debian.org/tracker/cve-", 30),
    ("security-tracker.debian.org/tracker/", 24),
    ("www.openwall.com/lists/oss-security/", 20),
    ("openwall.com/lists/oss-security/", 20),
    ("tracker.debian.org/pkg/", 18),
    ("www.debian.org/security/", 18),
    ("lists.debian.org/debian-security-announce/", 16),
    ("lists.debian.org/debian-lts-announce/", 14),
    ("nvd.nist.gov/vuln/detail/cve-", 10),
    ("access.redhat.com/security/cve/", 8),
    ("github.com/advisories/ghsa-", 7),
    ("downloads", -8),
    ("/auth/realms/", -10),
    ("/attachments/", -6),
    (".sig", -8),
    (".key", -8),
    (".asc", -8),
)
GITHUB_COMMIT_OR_PULL_RE = re.compile(
    r"^/[^/]+/[^/]+/(?:commit/[0-9a-f]{7,40}|pull/\d+)$",
    re.IGNORECASE,
)
GITLAB_COMMIT_OR_MR_RE = re.compile(
    r"^/(?:[^/]+/)+[^/]+/-/(?:commit/[0-9a-f]{7,40}|merge_requests/\d+)$",
    re.IGNORECASE,
)


def plan_frontier(seed_references: list[str]) -> list[str]:
    frontier: list[tuple[str, int, int]] = []
    seen_urls: set[str] = set()

    for index, reference in enumerate(seed_references):
        normalized = normalize_frontier_url(reference)
        if normalized is None or normalized in seen_urls:
            continue
        if match_reference_url(normalized) is not None:
            continue
        seen_urls.add(normalized)
        frontier.append((normalized, score_frontier_url(normalized), index))

    frontier.sort(key=lambda item: (-item[1], item[2]))
    return [url for url, _, _ in frontier[:MAX_FRONTIER_PAGES]]


def normalize_frontier_url(url: str) -> str | None:
    normalized = url.strip()
    if not normalized:
        return None
    normalized = urldefrag(normalized).url
    if normalized.startswith("http://www.openwall.com/lists/oss-security/"):
        return "https://" + normalized.removeprefix("http://")
    return normalized


def score_frontier_url(url: str) -> int:
    normalized = url.lower()
    score = sum(weight for marker, weight in FRONTIER_PRIORITY_RULES if marker in normalized)
    if "cve-" in normalized:
        score += 2
    if "security" in normalized:
        score += 1
    return score
