from __future__ import annotations

import json
from contextlib import contextmanager
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
from threading import Thread

from app.cve.browser.base import BrowserPageSnapshot
from app.cve.browser.base import PageLink
from app.cve.browser_agent_llm import MAX_KEY_LINKS
from app.cve.browser_agent_llm import NavigationContext
from app.cve.browser_agent_llm import build_llm_page_view
from app.cve.browser_agent_llm import build_navigation_context
from app.cve.browser_agent_llm import call_browser_agent_navigation


def test_build_llm_page_view_limits_key_links_to_15() -> None:
    snapshot = BrowserPageSnapshot(
        url="https://security-tracker.debian.org/tracker/CVE-2022-2509",
        final_url="https://security-tracker.debian.org/tracker/CVE-2022-2509",
        status_code=200,
        title="CVE-2022-2509",
        raw_html="<html></html>",
        accessibility_tree="heading \"CVE-2022-2509\"",
        markdown_content="tracker summary",
        links=[
            PageLink(
                url=f"https://example.com/link-{index}",
                text=f"link-{index}",
                context=f"context-{index}",
                is_cross_domain=index % 2 == 0,
                estimated_target_role="commit_page",
            )
            for index in range(20)
        ],
        page_role_hint="tracker_page",
        fetch_duration_ms=10,
    )

    page_view = build_llm_page_view(
        snapshot,
        candidates=[{"candidate_url": "https://example.com/fix.patch", "patch_type": "patch"}],
    )

    assert page_view.page_role == "tracker_page"
    assert len(page_view.key_links) == MAX_KEY_LINKS
    assert page_view.patch_candidates[0]["candidate_url"] == "https://example.com/fix.patch"


def test_build_navigation_context_includes_chain_and_browser_state() -> None:
    snapshot = BrowserPageSnapshot(
        url="https://security-tracker.debian.org/tracker/CVE-2022-2509",
        final_url="https://security-tracker.debian.org/tracker/CVE-2022-2509",
        status_code=200,
        title="CVE-2022-2509",
        raw_html="<html></html>",
        accessibility_tree="heading \"CVE-2022-2509\"",
        markdown_content="tracker summary",
        links=[],
        page_role_hint="tracker_page",
        fetch_duration_ms=10,
    )
    page_view = build_llm_page_view(snapshot, candidates=[])
    state = {
        "cve_id": "CVE-2022-2509",
        "budget": {"max_pages_total": 20, "max_llm_calls": 15},
        "page_role_history": [
            {
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-2509",
                "role": "advisory_page",
                "title": "NVD",
                "depth": "0",
            },
            {
                "url": "https://security-tracker.debian.org/tracker/CVE-2022-2509",
                "role": "tracker_page",
                "title": "Tracker",
                "depth": "1",
            },
        ],
        "navigation_chains": [
            {
                "chain_id": "chain-1",
                "chain_type": "advisory_to_patch",
                "status": "in_progress",
                "steps": [
                    {
                        "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-2509",
                        "page_role": "advisory_page",
                        "depth": 0,
                    }
                ],
                "expected_next_roles": ["commit_page", "download_page"],
            },
            {
                "chain_id": "chain-2",
                "chain_type": "advisory_to_patch",
                "status": "dead_end",
                "steps": [],
                "expected_next_roles": [],
            }
        ],
        "direct_candidates": [{"candidate_url": "https://example.com/fix.patch", "patch_type": "patch"}],
        "visited_urls": [
            "https://nvd.nist.gov/vuln/detail/CVE-2022-2509",
            "https://security-tracker.debian.org/tracker/CVE-2022-2509",
        ],
        "browser_snapshots": {
            "https://nvd.nist.gov/vuln/detail/CVE-2022-2509": {
                "title": "NVD",
                "markdown_content": "NVD summary",
            }
        },
    }

    context = build_navigation_context(state, page_view)

    assert context.cve_id == "CVE-2022-2509"
    assert context.current_page.page_role == "tracker_page"
    assert [chain["chain_id"] for chain in context.active_chains] == ["chain-1"]
    assert context.discovered_candidates[0]["candidate_url"] == "https://example.com/fix.patch"
    assert "nvd.nist.gov" in context.visited_domains
    assert context.navigation_path[0].startswith("advisory_page:")


class _LLMHandler(BaseHTTPRequestHandler):
    payloads: list[dict[str, object]] = []

    def do_POST(self) -> None:  # noqa: N802
        raw_length = int(self.headers["Content-Length"])
        raw_body = self.rfile.read(raw_length)
        self.__class__.payloads.append(json.loads(raw_body))

        response_body = json.dumps(
            {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "action": "expand_frontier",
                                    "reason_summary": "tracker 指向上游 commit",
                                    "confirmed_page_role": "tracker_page",
                                    "selected_urls": ["https://gitlab.com/org/proj/-/commit/abc1234"],
                                    "selected_candidate_keys": [],
                                    "cross_domain_justification": "标准跨域 patch 链路",
                                    "chain_updates": [],
                                    "new_chains": [],
                                },
                                ensure_ascii=False,
                            )
                        }
                    }
                ]
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


@contextmanager
def _serve_llm_response():
    _LLMHandler.payloads = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _LLMHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_call_browser_agent_navigation_sends_a11y_tree_and_chain_context(monkeypatch) -> None:
    context = NavigationContext(
        cve_id="CVE-2022-2509",
        budget_remaining={"max_pages_total": 20, "max_llm_calls": 15},
        navigation_path=[
            "advisory_page: https://nvd.nist.gov/vuln/detail/CVE-2022-2509",
            "tracker_page: https://security-tracker.debian.org/tracker/CVE-2022-2509",
        ],
        parent_page_summary="NVD summary",
        current_page=build_llm_page_view(
            BrowserPageSnapshot(
                url="https://security-tracker.debian.org/tracker/CVE-2022-2509",
                final_url="https://security-tracker.debian.org/tracker/CVE-2022-2509",
                status_code=200,
                title="CVE-2022-2509",
                raw_html="<html></html>",
                accessibility_tree='heading "CVE-2022-2509"\n  link "upstream fix"',
                markdown_content="tracker summary",
                links=[
                    PageLink(
                        url="https://gitlab.com/org/proj/-/commit/abc1234",
                        text="upstream fix",
                        context="Fixed upstream in commit abc1234",
                        is_cross_domain=True,
                        estimated_target_role="commit_page",
                    )
                ],
                page_role_hint="tracker_page",
                fetch_duration_ms=10,
            ),
            candidates=[],
        ),
        active_chains=[
            {
                "chain_id": "chain-1",
                "chain_type": "advisory_to_patch",
                "status": "in_progress",
                "steps": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2022-2509", "page_role": "advisory_page", "depth": 0}],
                "expected_next_roles": ["commit_page", "download_page"],
            }
        ],
        discovered_candidates=[],
        visited_domains=["nvd.nist.gov", "security-tracker.debian.org"],
    )

    with _serve_llm_response() as base_url:
        monkeypatch.setenv("LLM_BASE_URL", base_url)
        monkeypatch.setenv("LLM_API_KEY", "demo-key")
        monkeypatch.setenv("LLM_DEFAULT_MODEL", "qwen3.6-plus")

        decision = call_browser_agent_navigation(context)

    assert decision["action"] == "expand_frontier"
    assert decision["model_name"] == "qwen3.6-plus"

    request_payload = _LLMHandler.payloads[0]
    user_message = request_payload["messages"][1]["content"]
    serialized_context = json.loads(user_message)

    assert serialized_context["cve_id"] == "CVE-2022-2509"
    assert serialized_context["current_page"]["accessibility_tree_summary"].startswith("heading")
    assert serialized_context["active_chains"][0]["chain_id"] == "chain-1"
    assert serialized_context["navigation_path"][0].startswith("advisory_page:")


def test_call_browser_agent_navigation_raises_when_llm_response_missing_required_fields(monkeypatch) -> None:
    class _MissingFieldHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            response_body = json.dumps(
                {
                    "choices": [
                        {
                            "message": {
                                "content": json.dumps(
                                    {
                                        "action": "expand_frontier",
                                        "reason_summary": "missing fields",
                                    },
                                    ensure_ascii=False,
                                )
                            }
                        }
                    ]
                }
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)

        def log_message(self, format: str, *args) -> None:  # noqa: A003
            return

    @contextmanager
    def _serve_invalid_llm_response():
        server = ThreadingHTTPServer(("127.0.0.1", 0), _MissingFieldHandler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}"
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

    context = NavigationContext(
        cve_id="CVE-2022-2509",
        budget_remaining={"max_pages_total": 20},
        navigation_path=["tracker_page: https://security-tracker.debian.org/tracker/CVE-2022-2509"],
        parent_page_summary=None,
        current_page=build_llm_page_view(
            BrowserPageSnapshot(
                url="https://security-tracker.debian.org/tracker/CVE-2022-2509",
                final_url="https://security-tracker.debian.org/tracker/CVE-2022-2509",
                status_code=200,
                title="CVE-2022-2509",
                raw_html="<html></html>",
                accessibility_tree='heading "CVE-2022-2509"',
                markdown_content="tracker summary",
                links=[],
                page_role_hint="tracker_page",
                fetch_duration_ms=10,
            ),
            candidates=[],
        ),
        active_chains=[],
        discovered_candidates=[],
        visited_domains=["security-tracker.debian.org"],
    )

    with _serve_invalid_llm_response() as base_url:
        monkeypatch.setenv("LLM_BASE_URL", base_url)
        monkeypatch.setenv("LLM_API_KEY", "demo-key")
        monkeypatch.setenv("LLM_DEFAULT_MODEL", "qwen3.6-plus")

        import pytest

        with pytest.raises(ValueError, match="缺少字段"):
            call_browser_agent_navigation(context)
