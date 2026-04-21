from app.cve.chain_tracker import ChainTracker
import pytest


def test_chain_tracker_creates_advisory_chain_with_expected_next_roles() -> None:
    tracker = ChainTracker()

    chain = tracker.create_chain(
        chain_type="advisory_to_patch",
        initial_url="https://nvd.nist.gov/vuln/detail/CVE-2022-2509",
        page_role="advisory_page",
    )

    assert chain.chain_type == "advisory_to_patch"
    assert chain.status == "in_progress"
    assert chain.steps[0].url == "https://nvd.nist.gov/vuln/detail/CVE-2022-2509"
    assert chain.expected_next_roles == ["tracker_page", "commit_page", "download_page"]


def test_chain_tracker_extend_updates_expected_next_roles() -> None:
    tracker = ChainTracker()
    chain = tracker.create_chain(
        chain_type="advisory_to_patch",
        initial_url="https://nvd.nist.gov/vuln/detail/CVE-2022-2509",
        page_role="advisory_page",
    )

    tracker.extend_chain(
        chain.chain_id,
        url="https://security-tracker.debian.org/tracker/CVE-2022-2509",
        page_role="tracker_page",
        depth=1,
    )

    extended = tracker.get_all_chains()[0]
    assert len(extended.steps) == 2
    assert extended.steps[-1].page_role == "tracker_page"
    assert extended.expected_next_roles == ["commit_page", "download_page"]


def test_chain_tracker_complete_and_dead_end_update_status() -> None:
    tracker = ChainTracker()
    completed = tracker.create_chain(
        chain_type="tracker_to_commit",
        initial_url="https://security-tracker.debian.org/tracker/CVE-2022-2509",
        page_role="tracker_page",
    )
    dead_end = tracker.create_chain(
        chain_type="mailing_list_to_fix",
        initial_url="https://www.openwall.com/lists/oss-security/2022/08/01/1",
        page_role="mailing_list_page",
    )

    tracker.complete_chain(completed.chain_id)
    tracker.mark_dead_end(dead_end.chain_id)

    all_chains = {chain.chain_id: chain for chain in tracker.get_all_chains()}
    assert all_chains[completed.chain_id].status == "completed"
    assert all_chains[dead_end.chain_id].status == "dead_end"


def test_chain_tracker_get_active_chains_only_returns_in_progress() -> None:
    tracker = ChainTracker()
    active = tracker.create_chain(
        chain_type="tracker_to_commit",
        initial_url="https://security-tracker.debian.org/tracker/CVE-2022-2509",
        page_role="tracker_page",
    )
    done = tracker.create_chain(
        chain_type="mailing_list_to_fix",
        initial_url="https://www.openwall.com/lists/oss-security/2022/08/01/1",
        page_role="mailing_list_page",
    )
    tracker.complete_chain(done.chain_id)

    active_chains = tracker.get_active_chains()

    assert [chain.chain_id for chain in active_chains] == [active.chain_id]


def test_chain_tracker_round_trip_serialization_preserves_chain_state() -> None:
    tracker = ChainTracker()
    chain = tracker.create_chain(
        chain_type="advisory_to_patch",
        initial_url="https://nvd.nist.gov/vuln/detail/CVE-2022-2509",
        page_role="advisory_page",
    )
    tracker.extend_chain(
        chain.chain_id,
        url="https://security-tracker.debian.org/tracker/CVE-2022-2509",
        page_role="tracker_page",
        depth=1,
    )

    restored = ChainTracker.from_dict_list(tracker.to_dict_list())

    restored_chain = restored.get_all_chains()[0]
    assert restored_chain.chain_id == chain.chain_id
    assert restored_chain.steps[1].url == "https://security-tracker.debian.org/tracker/CVE-2022-2509"
    assert restored_chain.expected_next_roles == ["commit_page", "download_page"]


def test_chain_tracker_create_chain_rejects_when_max_chains_exceeded() -> None:
    tracker = ChainTracker()

    for index in range(5):
        tracker.create_chain(
            chain_type="advisory_to_patch",
            initial_url=f"https://example.com/{index}",
            page_role="advisory_page",
        )

    with pytest.raises(ValueError, match="max_chains_exceeded"):
        tracker.create_chain(
            chain_type="advisory_to_patch",
            initial_url="https://example.com/overflow",
            page_role="advisory_page",
        )
