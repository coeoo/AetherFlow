from __future__ import annotations

import re
from typing import Any


_PATCH_CANDIDATE_PATTERNS = [
    (re.compile(r"https?://[^\s\"'<>]+?\.diff\b[^\s\"'<>]*", re.IGNORECASE), "diff"),
    (re.compile(r"https?://[^\s\"'<>]+?\.patch\b[^\s\"'<>]*", re.IGNORECASE), "patch"),
    (
        re.compile(r"https?://[^\s\"'<>]+?\?[^\s\"'<>]*patch=[^\s\"'<>]+", re.IGNORECASE),
        "patch",
    ),
    (
        re.compile(
            r"https://github\.com/[^\s\"'<>]+/[^\s\"'<>]+/commit/[0-9a-f]{6,40}\b",
            re.IGNORECASE,
        ),
        "patch",
    ),
]


def analyze_page(snapshot: dict[str, Any]) -> list[dict[str, str]]:
    content = str(snapshot.get("content") or "")
    candidates: list[dict[str, str]] = []
    seen_urls: set[str] = set()

    for pattern, patch_type in _PATCH_CANDIDATE_PATTERNS:
        for match in pattern.finditer(content):
            candidate_url = match.group(0)
            if candidate_url in seen_urls:
                continue
            seen_urls.add(candidate_url)
            candidates.append(
                {
                    "candidate_url": candidate_url,
                    "patch_type": patch_type,
                }
            )

    return candidates
