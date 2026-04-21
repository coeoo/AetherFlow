from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from app.cve.frontier_planner import (
    GITHUB_COMMIT_OR_PULL_RE,
    GITLAB_COMMIT_OR_MR_RE,
    normalize_frontier_url,
)


def canonicalize_candidate_url(url: str) -> str:
    normalized = normalize_frontier_url(url) or url.strip()
    parsed = urlparse(normalized)
    normalized_query = urlencode(
        sorted(parse_qsl(parsed.query, keep_blank_values=True)),
        doseq=True,
    )
    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path[:-1]

    if path.lower().endswith((".patch", ".diff")):
        base_path = path.rsplit(".", 1)[0]
        if parsed.netloc.lower() == "github.com" and GITHUB_COMMIT_OR_PULL_RE.match(base_path):
            path = base_path
        elif GITLAB_COMMIT_OR_MR_RE.match(base_path):
            path = base_path

    if parsed.netloc.lower() == "github.com":
        segments = path.split("/")
        if len(segments) >= 4:
            segments[1] = segments[1].lower()
            segments[2] = segments[2].lower()
            path = "/".join(segments)

    return urlunparse(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            path,
            parsed.params,
            normalized_query,
            "",
        )
    )
