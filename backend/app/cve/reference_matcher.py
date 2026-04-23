from __future__ import annotations

import re
from urllib.parse import parse_qs, unquote, urlparse, urlunparse


_GITHUB_COMMIT_RE = re.compile(r"^/[^/]+/[^/]+/commit/[0-9a-f]{7,40}$", re.IGNORECASE)
_GITHUB_PULL_RE = re.compile(r"^/[^/]+/[^/]+/pull/\d+$", re.IGNORECASE)
_GITLAB_COMMIT_RE = re.compile(r"^/(?:[^/]+/)+[^/]+/-/commit/[0-9a-f]{7,40}$", re.IGNORECASE)
_GITLAB_MERGE_REQUEST_RE = re.compile(r"^/(?:[^/]+/)+[^/]+/-/merge_requests/\d+$", re.IGNORECASE)
_KERNEL_STABLE_SHORTLINK_RE = re.compile(r"^/stable/c/([0-9a-f]{7,40})$", re.IGNORECASE)


def match_reference_url(url: str) -> dict[str, str] | None:
    parsed = urlparse(url)
    normalized_path = parsed.path.lower()
    normalized_query = unquote(parsed.query).lower().replace(";", "&")

    if normalized_path.endswith(".debdiff") or ".debdiff" in normalized_query:
        return {
            "candidate_url": url,
            "patch_type": "debdiff",
        }

    if (
        normalized_path.endswith(".patch")
        or ".patch" in normalized_query
        or "patch=" in normalized_query
    ):
        return {
            "candidate_url": url,
            "patch_type": "patch",
        }

    if normalized_path.endswith(".diff") or ".diff" in normalized_query:
        return {
            "candidate_url": url,
            "patch_type": "diff",
        }

    if parsed.netloc == "github.com" and _GITHUB_COMMIT_RE.match(parsed.path):
        return {
            "candidate_url": f"{url}.patch",
            "patch_type": "github_commit_patch",
        }

    if parsed.netloc == "github.com" and _GITHUB_PULL_RE.match(parsed.path):
        base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
        return {
            "candidate_url": f"{base_url}.patch",
            "patch_type": "github_pull_patch",
        }

    if _GITLAB_COMMIT_RE.match(parsed.path):
        base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
        return {
            "candidate_url": f"{base_url}.patch",
            "patch_type": "gitlab_commit_patch",
        }

    if _GITLAB_MERGE_REQUEST_RE.match(parsed.path):
        base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
        return {
            "candidate_url": f"{base_url}.patch",
            "patch_type": "gitlab_merge_request_patch",
        }

    stable_match = _KERNEL_STABLE_SHORTLINK_RE.match(parsed.path)
    if parsed.netloc.endswith("git.kernel.org") and stable_match is not None:
        commit_id = stable_match.group(1)
        return {
            "candidate_url": urlunparse(
                (
                    parsed.scheme,
                    parsed.netloc,
                    "/pub/scm/linux/kernel/git/stable/linux.git/patch/",
                    "",
                    f"id={commit_id}",
                    "",
                )
            ),
            "patch_type": "kernel_commit_patch",
        }

    if parsed.netloc.endswith("git.kernel.org") and parsed.path.endswith("/commit") and "id" in parse_qs(parsed.query):
        commit_id = parse_qs(parsed.query).get("id", [""])[0]
        if re.fullmatch(r"[0-9a-f]{7,40}", commit_id, re.IGNORECASE):
            return {
                "candidate_url": urlunparse(
                    (
                        parsed.scheme,
                        parsed.netloc,
                        "/pub/scm/linux/kernel/git/stable/linux.git/patch/",
                        "",
                        f"id={commit_id}",
                        "",
                    )
                ),
                "patch_type": "kernel_commit_patch",
            }

    return None


def match_reference_urls(urls: list[str]) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    for url in urls:
        candidate = match_reference_url(url)
        if candidate is None:
            continue
        candidates.append(candidate)
    return candidates


def _is_distribution_patch_url(candidate_url: str) -> bool:
    parsed = urlparse(candidate_url)
    hostname = parsed.netloc.lower()
    normalized_path = parsed.path.lower()
    normalized_query = unquote(parsed.query).lower().replace(";", "&")
    if hostname == "patches.ubuntu.com":
        return True
    if hostname == "bugs.debian.org" and (
        normalized_path.endswith("bugreport.cgi")
        or "filename=" in normalized_query
    ):
        return True
    return False


CANDIDATE_PRIORITY: dict[str, int] = {
    "github_commit_patch": 100,
    "gitlab_commit_patch": 100,
    "kernel_commit_patch": 100,
    "github_pull_patch": 90,
    "gitlab_merge_request_patch": 90,
    "patch": 50,
    "diff": 50,
    "debdiff": 20,
}


def get_candidate_priority(patch_type: str, candidate_url: str | None = None) -> int:
    """返回 patch 类型的质量优先级。值越高表示候选质量越好。"""
    if candidate_url and patch_type in {"patch", "diff", "debdiff"}:
        if _is_distribution_patch_url(candidate_url):
            return 20
    return CANDIDATE_PRIORITY.get(patch_type, 50)
