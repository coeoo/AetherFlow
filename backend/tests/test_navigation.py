from app.cve.navigation import collect_follow_links


def test_collect_follow_links_prioritizes_target_cve_link_on_tracker_page() -> None:
    snapshot = {
        "url": "https://security-tracker.debian.org/tracker/source-package/gnutls28",
        "content": """
        <html>
          <body>
            <a href="/tracker/CVE-2015-6251">CVE-2015-6251</a>
            <a href="/tracker/CVE-2022-2509">CVE-2022-2509</a>
          </body>
        </html>
        """,
    }

    follow_links = collect_follow_links(snapshot, cve_id="CVE-2022-2509", max_results=2)

    assert follow_links == [
        "https://security-tracker.debian.org/tracker/CVE-2022-2509",
        "https://security-tracker.debian.org/tracker/CVE-2015-6251",
    ]
