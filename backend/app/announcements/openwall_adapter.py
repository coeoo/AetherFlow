from __future__ import annotations

import hashlib
import html
import re
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime

import httpx

_BASE_URL = "https://www.openwall.com/lists/oss-security"


def _fetch_text(url: str, timeout: float) -> str:
    response = httpx.get(url, timeout=timeout, follow_redirects=True)
    response.raise_for_status()
    return response.text


class OpenwallAdapter:
    def __init__(
        self,
        *,
        days_back: int = 3,
        max_documents: int = 5,
        timeout: float = 10.0,
    ) -> None:
        self.days_back = days_back
        self.max_documents = max_documents
        self.timeout = timeout

    def fetch_documents(self) -> list[dict[str, str]]:
        documents: list[dict[str, str]] = []

        for offset in range(self.days_back):
            day = datetime.now(UTC) - timedelta(days=offset)
            day_url = f"{_BASE_URL}/{day.strftime('%Y/%m/%d')}/"
            try:
                daily_html = _fetch_text(day_url, self.timeout)
            except Exception:
                continue
            for link in self._extract_message_links(daily_html, day_url):
                document = self._fetch_message_document(link)
                if document is None:
                    continue
                documents.append(document)
                if len(documents) >= self.max_documents:
                    return documents

        return documents

    def _extract_message_links(self, html: str, day_url: str) -> list[dict[str, str]]:
        if "oss-security mailing list" not in html:
            return []
        list_match = re.search(r"<ul>(.*?)</ul>", html, re.IGNORECASE | re.DOTALL)
        if list_match is None:
            return []

        seen_titles: set[str] = set()
        links: list[dict[str, str]] = []
        for item_match in re.finditer(
            r"<li>\s*<a href=\"([^\"]+)\">([^<]+)</a>.*?</li>",
            list_match.group(1),
            re.IGNORECASE | re.DOTALL,
        ):
            href, raw_title = item_match.groups()
            title = html_unescape(raw_title.strip())
            if not href:
                continue
            if title.startswith(("Re:", "RE:", "re:")):
                continue
            if title in seen_titles:
                continue
            seen_titles.add(title)
            links.append(
                {
                    "title": title,
                    "url": href if href.startswith("http") else f"{day_url}{href}",
                }
            )
        return links

    def _fetch_message_document(self, link: dict[str, str]) -> dict[str, str] | None:
        try:
            html = _fetch_text(link["url"], self.timeout)
        except Exception:
            return None
        pre_match = re.search(r"<pre>(.*?)</pre>", html, re.IGNORECASE | re.DOTALL)
        raw_content = html_unescape(pre_match.group(1)).strip() if pre_match is not None else ""
        if not raw_content:
            return None

        published_at = self._extract_date(raw_content)
        return {
            "source_name": "Openwall",
            "source_type": "openwall",
            "title": link["title"],
            "source_url": link["url"],
            "published_at": published_at,
            "source_item_key": link["url"],
            "raw_content": raw_content,
            "content_dedup_hash": hashlib.sha256(raw_content.encode("utf-8")).hexdigest(),
        }

    def _extract_date(self, raw_content: str) -> str | None:
        for line in raw_content.splitlines():
            stripped = line.strip()
            if not stripped.startswith("Date:"):
                continue
            parsed = parsedate_to_datetime(stripped.removeprefix("Date:").strip())
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            return parsed.isoformat()
        return None


def html_unescape(value: str) -> str:
    stripped = re.sub(r"<[^>]+>", "", value)
    return html.unescape(stripped)
