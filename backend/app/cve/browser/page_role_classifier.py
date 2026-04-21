from __future__ import annotations

from urllib.parse import unquote
from urllib.parse import urlparse


_DOWNLOAD_SUFFIXES = (".patch", ".diff", ".debdiff")
_REPOSITORY_HOSTS = ("github.com", "gitlab.com", "gitlab.gnome.org", "gitlab.freedesktop.org")


def classify_page_role(url: str) -> str:
    """基于 URL 形态做零成本页面角色分类。"""
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    path = parsed.path.lower()
    query = unquote(parsed.query).lower().replace(";", "&")
    is_github_advisory = "github.com" in host and path.startswith("/advisories/")

    if path.endswith(_DOWNLOAD_SUFFIXES) or any(suffix in query for suffix in _DOWNLOAD_SUFFIXES):
        return "download_page"

    if (
        "/commit/" in path
        or "/pull/" in path
        or "/merge_requests/" in path
        or path.endswith("/commit")
    ):
        return "commit_page"

    if host.endswith("security-tracker.debian.org") or "errata" in host or "/tracker/" in path:
        return "tracker_page"

    if (
        "openwall.com" in host
        or "oss-security" in path
        or "debian-security-announce" in path
        or "debian-lts-announce" in path
        or "lists.debian.org" in host
    ):
        return "mailing_list_page"

    if "bugzilla" in host or "show_bug" in path or "show_bug" in query:
        return "bugtracker_page"

    if (
        host.endswith("nvd.nist.gov")
        or is_github_advisory
        or "ghsa-" in path
        or "/vuln/detail/" in path
    ):
        return "advisory_page"

    if host in _REPOSITORY_HOSTS and _looks_like_repository_root(path):
        return "repository_page"

    return "unknown_page"


def _looks_like_repository_root(path: str) -> bool:
    segments = [segment for segment in path.split("/") if segment]
    if len(segments) < 2:
        return False
    if len(segments) == 2:
        return True
    return len(segments) == 3 and segments[2] in {"-", "tree", "blob"}
