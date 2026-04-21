from __future__ import annotations

from html.parser import HTMLParser
import re


MAX_MARKDOWN_CHARS = 2000


def extract_markdown_from_html(raw_html: str) -> str:
    """将 HTML 提取为简洁 markdown 文本，并截断到预算内。"""
    if not raw_html.strip():
        return ""

    markdown = _extract_with_html2text(raw_html)
    if markdown is None:
        parser = _FallbackMarkdownParser()
        parser.feed(raw_html)
        parser.close()
        markdown = parser.render()

    compacted = re.sub(r"\n{3,}", "\n\n", markdown)
    compacted = re.sub(r"[ \t]+\n", "\n", compacted)
    compacted = compacted.strip()
    if len(compacted) <= MAX_MARKDOWN_CHARS:
        return compacted
    return compacted[:MAX_MARKDOWN_CHARS].rsplit("\n", 1)[0].strip() or compacted[:MAX_MARKDOWN_CHARS].strip()


def _extract_with_html2text(raw_html: str) -> str | None:
    try:
        import html2text
    except ImportError:
        return None

    handler = html2text.HTML2Text()
    handler.body_width = 0
    handler.ignore_images = True
    handler.ignore_tables = False
    handler.single_line_break = False
    handler.wrap_links = False
    return handler.handle(raw_html)


class _FallbackMarkdownParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._parts: list[str] = []
        self._href_stack: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        normalized = tag.lower()
        if normalized in {"p", "div", "section", "article", "main", "ul", "ol", "table"}:
            self._parts.append("\n\n")
        elif normalized in {"li", "tr"}:
            self._parts.append("\n- ")
        elif normalized == "br":
            self._parts.append("\n")
        elif normalized in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            level = int(normalized[1])
            self._parts.append("\n\n" + "#" * level + " ")
        elif normalized == "a":
            href = ""
            for key, value in attrs:
                if key.lower() == "href" and value:
                    href = value
                    break
            self._href_stack.append(href)

    def handle_endtag(self, tag: str) -> None:
        normalized = tag.lower()
        if normalized == "a" and self._href_stack:
            href = self._href_stack.pop()
            if href:
                self._parts.append(f" ({href})")

    def handle_data(self, data: str) -> None:
        text = " ".join(data.split())
        if text:
            self._parts.append(text)

    def render(self) -> str:
        return "".join(self._parts)
