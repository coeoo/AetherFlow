from __future__ import annotations

from html import unescape
from html.parser import HTMLParser
import re
from typing import Any
from urllib.parse import urldefrag, urljoin, urlparse

from app.cve.reference_matcher import match_reference_urls


_ABSOLUTE_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_BUGZILLA_PATCH_ROW_RE = re.compile(
    r'<tr[^>]*class="[^"]*\bbz_patch\b[^"]*"[^>]*>(.*?)</tr>',
    re.IGNORECASE | re.DOTALL,
)
_HREF_RE = re.compile(r'href="([^"]+)"', re.IGNORECASE)


class _HrefCollector(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self._base_url = base_url
        self.urls: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:  # type: ignore[no-untyped-def]
        if tag.lower() != "a":
            return
        attr_map = dict(attrs)
        href = attr_map.get("href")
        if not isinstance(href, str):
            return
        normalized = unescape(href).strip()
        if not normalized:
            return
        self.urls.append(urljoin(self._base_url, normalized))


def analyze_page(snapshot: dict[str, Any]) -> list[dict[str, str]]:
    extracted_urls = _extract_reference_urls(snapshot)
    candidates = match_reference_urls(extracted_urls)
    if _looks_like_bugzilla_detail_page(snapshot):
        candidates.extend(_extract_bugzilla_raw_attachments(snapshot))
    return _dedupe_candidates(candidates)


def _extract_reference_urls(snapshot: dict[str, Any]) -> list[str]:
    base_url = str(snapshot.get("url") or "")
    content = str(snapshot.get("content") or "")
    extracted: list[str] = []
    seen: set[str] = set()

    parser = _HrefCollector(base_url)
    parser.feed(content)
    for url in parser.urls:
        if url not in seen:
            seen.add(url)
            extracted.append(url)

    for match in _ABSOLUTE_URL_RE.finditer(content):
        url = match.group(0)
        if url not in seen:
            seen.add(url)
            extracted.append(url)

    return extracted


def _looks_like_bugzilla_detail_page(snapshot: dict[str, Any]) -> bool:
    page_url = str(snapshot.get("url") or "")
    hostname = urlparse(page_url).hostname or ""
    if "bugzilla" not in hostname.lower():
        return False

    content = str(snapshot.get("content") or "")
    lowered = content.lower()
    return any(
        marker in lowered
        for marker in (
            "bz_patch",
            "attachment.cgi?id=",
            "show_bug.cgi?id=",
        )
    )


def _extract_bugzilla_raw_attachments(snapshot: dict[str, Any]) -> list[dict[str, str]]:
    current_url = str(snapshot.get("url") or "")
    content = str(snapshot.get("content") or "")
    candidates: list[dict[str, str]] = []

    # Bugzilla 页面里同一个附件通常同时出现 raw / edit / diff 多种入口，这里只保留 raw attachment。
    for row_html in _BUGZILLA_PATCH_ROW_RE.findall(content):
        for href in _HREF_RE.findall(row_html):
            normalized_href = unescape(href).strip()
            lowered_href = normalized_href.lower()
            if "attachment.cgi?id=" not in lowered_href:
                continue
            if "action=" in lowered_href:
                continue
            candidates.append(
                {
                    "candidate_url": urljoin(current_url, normalized_href),
                    "patch_type": "bugzilla_attachment_patch",
                }
            )
            break

    return candidates


def _dedupe_candidates(candidates: list[dict[str, str]]) -> list[dict[str, str]]:
    deduped: list[dict[str, str]] = []
    seen_urls: set[str] = set()
    for candidate in candidates:
        candidate_url = candidate.get("candidate_url", "")
        normalized_url = urldefrag(candidate_url).url
        if not normalized_url or normalized_url in seen_urls:
            continue
        seen_urls.add(normalized_url)
        deduped.append(
            {
                "candidate_url": normalized_url,
                "patch_type": candidate["patch_type"],
            }
        )
    return deduped
