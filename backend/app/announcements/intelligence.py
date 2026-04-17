from __future__ import annotations


def classify_linux_relevance(title: str, content: str) -> tuple[bool, float, str]:
    haystack = f"{title}\n{content}".lower()
    keywords = [
        "linux",
        "kernel",
        "openssl",
        "openssh",
        "ubuntu",
        "debian",
        "red hat",
        "container",
    ]
    matched = [keyword for keyword in keywords if keyword in haystack]

    if matched:
        primary_keyword = matched[0]
        return (
            True,
            0.9,
            f"检测到与 Linux 生态相关的安全公告，关键线索包含 {primary_keyword}。",
        )

    return (
        False,
        0.35,
        "当前公告未命中 Linux 生态的明确关键线索，建议后续按需人工复核。",
    )
