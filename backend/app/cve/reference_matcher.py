from __future__ import annotations

import re
from urllib.parse import parse_qs, unquote, urlparse, urlunparse


_GITHUB_COMMIT_RE = re.compile(r"^/[^/]+/[^/]+/commit/[0-9a-f]{7,40}$", re.IGNORECASE)
_GITHUB_PULL_RE = re.compile(r"^/[^/]+/[^/]+/pull/\d+$", re.IGNORECASE)
_GITLAB_COMMIT_RE = re.compile(r"^/(?:[^/]+/)+[^/]+/-/commit/[0-9a-f]{7,40}$", re.IGNORECASE)
_GITLAB_MERGE_REQUEST_RE = re.compile(r"^/(?:[^/]+/)+[^/]+/-/merge_requests/\d+$", re.IGNORECASE)
_KERNEL_STABLE_SHORTLINK_RE = re.compile(r"^/stable/c/([0-9a-f]{7,40})$", re.IGNORECASE)
_BITBUCKET_COMMIT_RE = re.compile(r"^/[^/]+/[^/]+/commits?/[0-9a-f]{7,40}$", re.IGNORECASE)
_BITBUCKET_PULL_RE = re.compile(r"^/[^/]+/[^/]+/pull-requests/\d+$", re.IGNORECASE)
_GITEE_COMMIT_RE = re.compile(r"^/[^/]+/[^/]+/commit/[0-9a-f]{7,40}$", re.IGNORECASE)
_AOSP_GITILES_COMMIT_RE = re.compile(r"^/(.+)/\+/([0-9a-f]{7,40})$", re.IGNORECASE)
_BUGZILLA_HOSTS: set[str] = {
    "bugzilla.redhat.com",
    "bugzilla.suse.com",
    "bugzilla.kernel.org",
    "bugzilla.mozilla.org",
    "bugzilla.gnome.org",
    "bugs.gentoo.org",
}
_BUGZILLA_ATTACHMENT_PATH_RE = re.compile(r"^/attachment\.cgi$", re.IGNORECASE)


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

    # Bitbucket commit → patch
    if parsed.netloc == "bitbucket.org" and _BITBUCKET_COMMIT_RE.match(parsed.path):
        base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
        return {
            "candidate_url": f"{base_url}/raw",
            "patch_type": "bitbucket_commit_patch",
        }

    # Bitbucket pull request → patch
    if parsed.netloc == "bitbucket.org" and _BITBUCKET_PULL_RE.match(parsed.path):
        base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
        return {
            "candidate_url": f"{base_url}.patch",
            "patch_type": "bitbucket_pull_patch",
        }

    # Gitee commit → patch
    if parsed.netloc == "gitee.com" and _GITEE_COMMIT_RE.match(parsed.path):
        base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
        return {
            "candidate_url": f"{base_url}.patch",
            "patch_type": "gitee_commit_patch",
        }

    # AOSP android.googlesource.com gitiles commit → patch
    # 仅接受恰好一段 /+/ 的 commit 形态，拒绝 /+/log/、/+/refs/、多重 /+/ 等非 commit 路径。
    if parsed.netloc == "android.googlesource.com" and parsed.path.count("/+/") == 1:
        aosp_match = _AOSP_GITILES_COMMIT_RE.match(parsed.path)
        if aosp_match is not None:
            repo_path = aosp_match.group(1)
            commit_id = aosp_match.group(2)
            return {
                "candidate_url": urlunparse(
                    (
                        parsed.scheme,
                        parsed.netloc,
                        f"/{repo_path}/+/{commit_id}.patch",
                        "",
                        "",
                        "",
                    )
                ),
                "patch_type": "aosp_commit_patch",
            }

    # Bugzilla attachment → patch
    # 限定 hostname allowlist 与 path 形态，避免任意域名 /attachment.cgi 误匹配。
    if (
        parsed.netloc.lower() in _BUGZILLA_HOSTS
        and _BUGZILLA_ATTACHMENT_PATH_RE.match(parsed.path)
    ):
        attachment_ids = parse_qs(parsed.query).get("id", [])
        if any(re.fullmatch(r"\d+", aid) for aid in attachment_ids):
            return {
                "candidate_url": url,
                "patch_type": "bugzilla_attachment_patch",
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


_DISTRIBUTION_HOSTS: set[str] = {
    "patches.ubuntu.com",
    "bugs.debian.org",
    "src.fedoraproject.org",
    "download.opensuse.org",
    "archive.archlinux.org",
    "deb.debian.org",
    "security.debian.org",
}


def _is_distribution_patch_url(candidate_url: str) -> bool:
    parsed = urlparse(candidate_url)
    hostname = parsed.netloc.lower()
    normalized_path = parsed.path.lower()
    normalized_query = unquote(parsed.query).lower().replace(";", "&")
    if hostname in _DISTRIBUTION_HOSTS:
        return True
    if hostname == "bugs.debian.org" and (
        normalized_path.endswith("bugreport.cgi")
        or "filename=" in normalized_query
    ):
        return True
    if hostname.endswith(".ubuntu.com") and "patch" in normalized_path:
        return True
    if hostname == "access.redhat.com" and "errata" in normalized_path:
        return True
    return False


# 历史快照 — 真相已迁移到 candidate_scoring._PATCH_TYPE_BASE_SCORE / get_type_priority；
# 这里保留以兼容外部读取 CANDIDATE_PRIORITY 的代码，新增 patch_type 应改 candidate_scoring。
CANDIDATE_PRIORITY: dict[str, int] = {
    "github_commit_patch": 100,
    "gitlab_commit_patch": 100,
    "kernel_commit_patch": 100,
    "bitbucket_commit_patch": 95,
    "gitee_commit_patch": 90,
    "aosp_commit_patch": 90,
    "github_pull_patch": 90,
    "gitlab_merge_request_patch": 90,
    "bitbucket_pull_patch": 85,
    "patch": 50,
    "diff": 50,
    "bugzilla_attachment_patch": 40,
    "debdiff": 20,
}

KNOWN_PATCH_TYPES: frozenset[str] = frozenset(CANDIDATE_PRIORITY)


def get_candidate_priority(patch_type: str, candidate_url: str | None = None) -> int:
    """返回 patch 类型的质量优先级。值越高表示候选质量越好。

    type-only priority 委托至 candidate_scoring.get_type_priority；
    distro URL 降权外壳保留在本函数（distro URL 是 URL 语义，不是 type 语义）。
    """
    from app.cve.candidate_scoring import get_type_priority

    if candidate_url and patch_type in {"patch", "diff", "debdiff"}:
        if _is_distribution_patch_url(candidate_url):
            return 20
    return get_type_priority(patch_type)
