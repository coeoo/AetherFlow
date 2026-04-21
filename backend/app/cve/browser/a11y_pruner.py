from __future__ import annotations

from typing import Any


MAX_A11Y_CHARS = 6000
KEEP_ROLES = {
    "link",
    "heading",
    "text",
    "list",
    "listitem",
    "paragraph",
    "table",
    "row",
    "cell",
    "StaticText",
}


def prune_accessibility_tree(raw_snapshot: dict[str, Any] | None) -> str:
    """将原始 a11y 树裁剪成适合 LLM 阅读的缩进文本。"""
    if not raw_snapshot:
        return ""

    lines: list[str] = []
    _collect_lines(raw_snapshot, depth=0, lines=lines)
    serialized = "\n".join(lines).strip()
    if len(serialized) <= MAX_A11Y_CHARS:
        return serialized

    truncated = serialized[:MAX_A11Y_CHARS].rsplit("\n", 1)[0].strip()
    if truncated:
        return truncated
    return serialized[:MAX_A11Y_CHARS].strip()


def _collect_lines(node: dict[str, Any], *, depth: int, lines: list[str]) -> None:
    role = str(node.get("role") or "")
    children = node.get("children") or []
    keep_current = role in KEEP_ROLES
    child_depth = depth

    if keep_current:
        line = _format_node_line(node, role=role, depth=depth)
        if line:
            lines.append(line)
        child_depth = depth + 1

    if not isinstance(children, list):
        return

    for child in children:
        if isinstance(child, dict):
            _collect_lines(child, depth=child_depth, lines=lines)


def _format_node_line(node: dict[str, Any], *, role: str, depth: int) -> str:
    normalized_role = "text" if role == "StaticText" else role
    name = _normalize_text(node.get("name"))
    url = _normalize_text(node.get("url"))
    line = "  " * depth + normalized_role
    if name:
        line += f' "{name}"'
    if url:
        line += f" -> {url}"
    return line


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    text = " ".join(str(value).split())
    return text.strip()
