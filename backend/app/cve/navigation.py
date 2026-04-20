from __future__ import annotations

from collections.abc import Sequence
from html.parser import HTMLParser
from html import unescape
import re
from urllib.parse import urljoin, urlparse


_LINK_CONTEXT_RADIUS = 180
_MIN_FOLLOW_LINK_SCORE = 6
_NAVIGATION_SIGNAL_WEIGHTS: tuple[tuple[str, int], ...] = (
    ("attachment.cgi?id=", 9),
    ("filename=", 8),
    ("att=1", 8),
    ("debdiff", 8),
    (".debdiff", 8),
    (".patch", 8),
    (" patch", 8),
    ("patch ", 8),
    (".diff", 7),
    (" diff", 7),
    ("diff ", 7),
    ("attachment", 7),
    ("changeset", 6),
    ("backport", 6),
    ("merge request", 5),
    ("merge_requests", 5),
    ("commit", 5),
    ("pull", 4),
    ("fix", 4),
    ("download", 3),
    ("upstream", 3),
    ("tracker", 3),
    ("cve-", 3),
    ("security", 1),
    ("advisory", 1),
)
_GENERIC_LINK_TEXTS = frozenset(
    {
        "",
        "details",
        "detail",
        "more",
        "read more",
        "view",
        "here",
        "link",
        "landing",
        "landing page",
    }
)


class _LinkHTMLParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self._base_url = base_url
        self.links: list[dict[str, str]] = []
        self._current_href: str | None = None
        self._current_raw_href: str | None = None
        self._current_title = ""
        self._current_text_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:  # type: ignore[no-untyped-def]
        if tag.lower() != "a":
            return
        attr_map = dict(attrs)
        href = attr_map.get("href")
        if not isinstance(href, str) or not href.strip():
            return
        self._current_href = urljoin(self._base_url, href)
        self._current_raw_href = href
        self._current_title = _normalize_space(attr_map.get("title", ""))
        self._current_text_parts = []

    def handle_data(self, data: str) -> None:
        if self._current_href is not None:
            self._current_text_parts.append(data.strip())

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "a" or self._current_href is None:
            return
        self.links.append(
            {
                "url": self._current_href,
                "href": self._current_raw_href or self._current_href,
                "text": " ".join(part for part in self._current_text_parts if part),
                "title": self._current_title,
            }
        )
        self._current_href = None
        self._current_raw_href = None
        self._current_title = ""
        self._current_text_parts = []


def collect_follow_links(
    snapshot: dict[str, object],
    *,
    cve_id: str | None = None,
    max_results: int = 3,
) -> list[str]:
    current_url = str(snapshot.get("url") or "")
    content = str(snapshot.get("content") or "")
    if not current_url or not content:
        return []

    parser = _LinkHTMLParser(current_url)
    parser.feed(content)
    extracted_links: list[dict[str, str]] = []
    search_start = 0
    for item in parser.links:
        context, search_start = _extract_link_context(
            content,
            raw_href=item.get("href", item["url"]),
            link_text=item.get("text", ""),
            link_title=item.get("title", ""),
            search_start=search_start,
        )
        extracted_links.append(
            {
                "url": item["url"],
                "text": _normalize_space(item.get("text", "")),
                "title": _normalize_space(item.get("title", "")),
                "context": context,
            }
        )

    ranked = _rank_navigation_links(
        extracted_links,
        current_url=current_url,
        cve_id=cve_id,
        max_results=max_results,
        min_score=_MIN_FOLLOW_LINK_SCORE,
    )
    return [item["url"] for item in ranked]


def _rank_navigation_links(
    links: list[dict[str, str]],
    *,
    current_url: str,
    cve_id: str | None,
    max_results: int,
    min_score: int,
) -> list[dict[str, str]]:
    merged: dict[str, dict[str, str]] = {}
    order: list[str] = []
    for item in links:
        normalized_url = _normalize_url(item["url"])
        if not _is_same_registrable_domain(current_url, normalized_url):
            continue
        normalized_item = {
            "url": normalized_url,
            "text": _normalize_space(item.get("text", "")),
            "title": _normalize_space(item.get("title", "")),
            "context": _normalize_space(item.get("context", "")),
        }
        if normalized_url not in merged:
            merged[normalized_url] = normalized_item
            order.append(normalized_url)
            continue
        merged[normalized_url] = _merge_navigation_link(merged[normalized_url], normalized_item)

    ranked: list[tuple[int, int, dict[str, str]]] = []
    for index, normalized_url in enumerate(order):
        item = merged[normalized_url]
        score = _score_navigation_link(item, current_url=current_url, cve_id=cve_id)
        if score < min_score:
            continue
        ranked.append((score, index, item))

    ranked.sort(key=lambda entry: (-entry[0], entry[1]))
    return [item for _, _, item in ranked[:max_results]]


def _merge_navigation_link(existing: dict[str, str], incoming: dict[str, str]) -> dict[str, str]:
    merged = dict(existing)
    merged["text"] = _prefer_anchor_fragment(existing.get("text", ""), incoming.get("text", ""))
    merged["title"] = _prefer_anchor_fragment(existing.get("title", ""), incoming.get("title", ""))
    merged["context"] = _merge_text_fragments(existing.get("context", ""), incoming.get("context", ""))
    return merged


def _prefer_anchor_fragment(left: str, right: str) -> str:
    best_fragment = _normalize_space(left)
    best_score = _anchor_fragment_priority(best_fragment)
    normalized = _normalize_space(right)
    candidate_score = _anchor_fragment_priority(normalized)
    if candidate_score > best_score:
        return normalized
    return best_fragment


def _anchor_fragment_priority(text: str) -> tuple[int, int]:
    normalized = _normalize_space(text).lower()
    if not normalized:
        return (-1, -1)
    is_generic = normalized in _GENERIC_LINK_TEXTS
    generic_penalty = -1 if is_generic else 0
    length_score = 0 if is_generic else len(normalized)
    return (_keyword_signal_score(normalized) + generic_penalty, length_score)


def _merge_text_fragments(left: str, right: str) -> str:
    parts: list[str] = []
    for value in (left, right):
        normalized = _normalize_space(value)
        if normalized and normalized not in parts:
            parts.append(normalized)
    return " | ".join(parts)


def _score_navigation_link(
    item: dict[str, str],
    *,
    current_url: str,
    cve_id: str | None,
) -> int:
    url_text = item["url"].lower()
    title_text = _normalize_space(item.get("title", "")).lower()
    anchor_text = _normalize_space(item.get("text", "")).lower()
    context_text = _normalize_space(item.get("context", "")).lower()

    score = _keyword_signal_score(url_text)
    score += _keyword_signal_score(title_text)
    score += _keyword_signal_score(context_text)
    if anchor_text and anchor_text not in _GENERIC_LINK_TEXTS:
        score += _keyword_signal_score(anchor_text) + 1

    if _is_same_registrable_domain(current_url, item["url"]):
        score += 4
    if cve_id:
        normalized_cve_id = cve_id.lower()
        if (
            normalized_cve_id in url_text
            or normalized_cve_id in title_text
            or normalized_cve_id in anchor_text
            or normalized_cve_id in context_text
        ):
            score += 40
    return score


def _keyword_signal_score(text: str) -> int:
    normalized = text.lower()
    return sum(weight for keyword, weight in _NAVIGATION_SIGNAL_WEIGHTS if keyword in normalized)


def _extract_link_context(
    html_text: str,
    *,
    raw_href: str,
    link_text: str,
    link_title: str,
    search_start: int,
) -> tuple[str, int]:
    markers = [
        raw_href,
        raw_href.replace("&", "&amp;"),
        link_title,
        link_text,
    ]
    anchor_pos = _find_marker_position(html_text.lower(), markers, start=search_start)
    if anchor_pos < 0 and search_start > 0:
        anchor_pos = _find_marker_position(html_text.lower(), markers, start=0)
    if anchor_pos < 0:
        return _normalize_space(f"{link_title} {link_text}"), search_start

    start = max(0, anchor_pos - _LINK_CONTEXT_RADIUS)
    end = min(len(html_text), anchor_pos + max(len(raw_href), len(link_text), 1) + 40)
    snippet = html_text[start:end]
    cleaned = _clean_html_excerpt(snippet)
    return cleaned, anchor_pos + 1


def _find_marker_position(text_lower: str, markers: Sequence[str], *, start: int) -> int:
    for marker in markers:
        normalized_marker = _normalize_space(marker).lower()
        if len(normalized_marker) < 4:
            continue
        position = text_lower.find(normalized_marker, start)
        if position >= 0:
            return position
    return -1


def _clean_html_excerpt(snippet: str) -> str:
    without_tags = re.sub(r"<[^>]+>", " ", snippet)
    return _normalize_space(unescape(without_tags))


def _normalize_space(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _normalize_url(url: str) -> str:
    return url.split("#", 1)[0].rstrip("/")


def _is_same_registrable_domain(base_url: str, candidate_url: str) -> bool:
    base_host = urlparse(base_url).hostname or ""
    candidate_host = urlparse(candidate_url).hostname or ""
    if not base_host or not candidate_host:
        return False
    return ".".join(base_host.split(".")[-2:]) == ".".join(candidate_host.split(".")[-2:])
