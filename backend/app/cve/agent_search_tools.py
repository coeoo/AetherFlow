from __future__ import annotations

import re
from urllib.parse import urlparse

from app.cve.browser.base import PageLink
from app.cve.browser.page_role_classifier import classify_page_role
from app.cve.frontier_planner import normalize_frontier_url, score_frontier_url

GLOBAL_NOISE_PATH_FRAGMENTS = (
    "/login",
    "/signin",
    "/signup",
    "/register",
    "/msgid-search/",
    "/general",
    "/dashboard",
    "/about",
    "/contact",
    "/privacy",
    "/terms",
    "/help",
    "/features/",
    "/pricing",
    "/enterprise",
    "/vuln-metrics/cvss/",
)
MAILING_LIST_NOISE_TEXTS = {
    "date prev",
    "date next",
    "date index",
    "thread prev",
    "thread next",
    "author prev",
    "author next",
}
MAILING_LIST_NOISE_PATH_FRAGMENTS = (
    "/maillist.html",
    "/threads.html",
    "/subject.html",
    "/author.html",
    "/date.html",
    "/prev-date.html",
    "/next-date.html",
    "/thrd",
)
CVE_ID_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def extract_cve_ids(*values: str) -> set[str]:
    matched_ids: set[str] = set()
    for value in values:
        if not value:
            continue
        matched_ids.update(match.upper() for match in CVE_ID_RE.findall(value))
    return matched_ids


def score_frontier_candidate(
    *,
    normalized_url: str,
    link: PageLink,
    target_cve_id: str,
    source_page_role: str = "",
) -> int:
    target_role = link.estimated_target_role or classify_page_role(normalized_url)
    score = score_frontier_url(normalized_url)
    role_bonus = {
        "commit_page": 60,
        "pull_request_page": 55,
        "merge_request_page": 55,
        "download_page": 25,
        "tracker_page": 15,
        "bugtracker_page": 10,
        "repository_page": 5,
    }
    score += role_bonus.get(target_role, 0)
    if source_page_role == "tracker_page":
        tracker_source_bonus = {
            "commit_page": 220,
            "pull_request_page": 210,
            "merge_request_page": 210,
            "download_page": 180,
            "tracker_page": 20,
            "bugtracker_page": -20,
            "advisory_page": -40,
        }
        score += tracker_source_bonus.get(target_role, 0)
    elif source_page_role in {
        "mailing_list_page",
        "bugtracker_page",
        "repository_page",
    }:
        stage_source_bonus = {
            "commit_page": 180,
            "pull_request_page": 170,
            "merge_request_page": 170,
            "download_page": 140,
            "tracker_page": 40,
            "bugtracker_page": -20,
            "advisory_page": -40,
            "repository_page": -60,
        }
        score += stage_source_bonus.get(target_role, 0)
    matched_cve_ids = extract_cve_ids(normalized_url, link.text, link.context)
    if target_cve_id:
        if target_cve_id in matched_cve_ids:
            score += 120
        elif matched_cve_ids:
            score -= 160
    return score


def is_navigation_noise_url(url: str) -> bool:
    normalized = url.lower()
    parsed = urlparse(normalized)
    if parsed.scheme in {"mailto", "javascript", "tel"}:
        return True
    if normalized in {
        "https://www.debian.org/security/",
        "https://www.debian.org/lts/security/",
        "https://www.debian.org/security/faq",
        "https://access.redhat.com/security",
        "https://access.redhat.com/security/",
        "https://access.redhat.com/security/vulnerabilities",
        "https://access.redhat.com/security/security-updates/",
    }:
        return True
    path = parsed.path or "/"
    return any(fragment in path for fragment in GLOBAL_NOISE_PATH_FRAGMENTS)


def is_mailing_list_navigation_noise(link: PageLink) -> bool:
    normalized_text = " ".join(link.text.lower().split())
    normalized_context = " ".join(link.context.lower().split())
    normalized_url = link.url.lower()
    path = urlparse(normalized_url).path or "/"
    if normalized_text in MAILING_LIST_NOISE_TEXTS:
        return True
    if "mail archive navigation" in normalized_context:
        return True
    if normalized_context.startswith("message-id:"):
        return True
    if normalized_context.startswith("to:") or normalized_context.startswith("from:"):
        return True
    if normalized_context.startswith("reply-to:") or normalized_context.startswith(
        "mail-followup-to:"
    ):
        return True
    if normalized_context.startswith("prev by date:") or normalized_context.startswith(
        "next by date:"
    ):
        return True
    if normalized_context.startswith(
        "previous by thread:"
    ) or normalized_context.startswith("next by thread:"):
        return True
    return any(fragment in path for fragment in MAILING_LIST_NOISE_PATH_FRAGMENTS)


def is_high_value_frontier_link(link: PageLink) -> bool:
    target_url = (normalize_frontier_url(link.url) or link.url).lower()
    target_role = (link.estimated_target_role or classify_page_role(target_url)).strip()
    if "security-tracker.debian.org/tracker/" in target_url:
        return True
    if target_role in {
        "tracker_page",
        "commit_page",
        "pull_request_page",
        "merge_request_page",
        "download_page",
    }:
        if target_url in {
            "https://www.debian.org/security/",
            "https://www.debian.org/lts/security/",
            "https://www.debian.org/security/faq",
        }:
            return False
        return True
    return any(
        marker in target_url
        for marker in (
            "/commit/",
            "/pull/",
            "/merge_requests/",
            ".patch",
            ".diff",
            ".debdiff",
        )
    )


def should_skip_frontier_link(source_page_role: str, link: PageLink) -> bool:
    normalized_url = normalize_frontier_url(link.url)
    if normalized_url is None:
        return True
    if is_high_value_frontier_link(link):
        return False
    if is_navigation_noise_url(normalized_url):
        return True
    if (
        source_page_role == "mailing_list_page"
        and is_mailing_list_navigation_noise(link)
    ):
        return True
    return False


def filter_frontier_links(
    source_page_role: str,
    links: list[PageLink],
) -> list[PageLink]:
    filtered_links: list[PageLink] = []
    seen_urls: set[str] = set()
    for link in links:
        normalized_url = normalize_frontier_url(link.url)
        if normalized_url is None or normalized_url in seen_urls:
            continue
        seen_urls.add(normalized_url)
        if should_skip_frontier_link(source_page_role, link):
            continue
        filtered_links.append(link)
    return filtered_links


def textual_fix_signal_score(item: dict[str, object]) -> int:
    text = " ".join(
        [
            str(item.get("url") or ""),
            str(item.get("anchor_text") or ""),
            str(item.get("link_context") or ""),
        ]
    ).lower()
    score = 0
    for keyword in (
        "fix",
        "fixed",
        "patch",
        "commit",
        "pull request",
        "merge request",
        "security",
        "vulnerab",
        "cve-",
    ):
        if keyword in text:
            score += 1
    return score


def coerce_rank(value: object, *, default: int = 999) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
