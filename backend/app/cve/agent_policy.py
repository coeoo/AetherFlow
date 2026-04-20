from __future__ import annotations


DEFAULT_PATCH_AGENT_BUDGET = {
    "max_pages_total": 12,
    "max_depth": 4,
    "max_cross_domain_expansions": 4,
    "max_download_attempts": 6,
}


def build_default_budget() -> dict[str, int]:
    return dict(DEFAULT_PATCH_AGENT_BUDGET)
