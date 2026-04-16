from app.announcements.openwall_adapter import OpenwallAdapter


def test_openwall_adapter_extracts_non_reply_messages_from_daily_index(
    monkeypatch,
) -> None:
    daily_index_html = """
    <html>
      <body>
        <h2>oss-security mailing list</h2>
        <ul>
          <li><a href="1">OpenSSL advisory</a> (alice@example.com)</li>
          <li><a href="2">Re: OpenSSL advisory</a> (bob@example.com)</li>
          <li><a href="3">Kernel update</a> (carol@example.com)</li>
        </ul>
      </body>
    </html>
    """

    message_html = """
    <html>
      <body>
        <pre>
        From: Alice Example
        Date: Tue, 15 Apr 2026 09:00:00 +0000

        OpenSSL remote code execution vulnerability details.
        Linux distributions are affected.
        </pre>
      </body>
    </html>
    """

    pages = {
        "https://www.openwall.com/lists/oss-security/2026/04/15/": daily_index_html,
        "https://www.openwall.com/lists/oss-security/2026/04/15/1": message_html,
        "https://www.openwall.com/lists/oss-security/2026/04/15/3": message_html.replace(
            "OpenSSL advisory",
            "Kernel update",
        ),
    }

    monkeypatch.setattr(
        "app.announcements.openwall_adapter._fetch_text",
        lambda url, timeout: pages[url],
    )

    adapter = OpenwallAdapter(days_back=2, max_documents=5)

    documents = adapter.fetch_documents()

    assert [item["title"] for item in documents] == [
        "OpenSSL advisory",
        "Kernel update",
    ]


def test_openwall_adapter_fetches_message_body_and_returns_standard_document(
    monkeypatch,
) -> None:
    daily_index_html = """
    <html>
      <body>
        <h2>oss-security mailing list</h2>
        <ul>
          <li><a href="42">OpenSSL advisory</a> (alice@example.com)</li>
        </ul>
      </body>
    </html>
    """
    message_html = """
    <html>
      <body>
        <pre>
        From: Alice Example
        Date: Tue, 15 Apr 2026 09:00:00 +0000

        OpenSSL remote code execution vulnerability details.
        Linux distributions are affected.
        </pre>
      </body>
    </html>
    """

    pages = {
        "https://www.openwall.com/lists/oss-security/2026/04/15/": daily_index_html,
        "https://www.openwall.com/lists/oss-security/2026/04/15/42": message_html,
    }
    monkeypatch.setattr(
        "app.announcements.openwall_adapter._fetch_text",
        lambda url, timeout: pages[url],
    )

    adapter = OpenwallAdapter(days_back=2, max_documents=5)

    document = adapter.fetch_documents()[0]

    assert document["source_name"] == "Openwall"
    assert document["source_type"] == "openwall"
    assert document["title"] == "OpenSSL advisory"
    assert document["source_url"] == "https://www.openwall.com/lists/oss-security/2026/04/15/42"
    assert document["source_item_key"] == "https://www.openwall.com/lists/oss-security/2026/04/15/42"
    assert "Linux distributions are affected." in document["raw_content"]
    assert len(document["content_dedup_hash"]) == 64


def test_openwall_adapter_builds_stable_source_item_key_from_message_url(
    monkeypatch,
) -> None:
    daily_index_html = """
    <html>
      <body>
        <h2>oss-security mailing list</h2>
        <ul>
          <li><a href="42">OpenSSL advisory</a> (alice@example.com)</li>
        </ul>
      </body>
    </html>
    """
    message_html = """
    <html>
      <body><pre>Date: Tue, 15 Apr 2026 09:00:00 +0000\n\nBody</pre></body>
    </html>
    """

    pages = {
        "https://www.openwall.com/lists/oss-security/2026/04/15/": daily_index_html,
        "https://www.openwall.com/lists/oss-security/2026/04/15/42": message_html,
    }
    monkeypatch.setattr(
        "app.announcements.openwall_adapter._fetch_text",
        lambda url, timeout: pages[url],
    )

    adapter = OpenwallAdapter(days_back=2, max_documents=5)

    first = adapter.fetch_documents()[0]
    second = adapter.fetch_documents()[0]

    assert first["source_item_key"] == second["source_item_key"]
