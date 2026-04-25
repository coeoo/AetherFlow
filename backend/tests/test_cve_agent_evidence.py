import uuid

from app.cve import agent_nodes
from app.cve.agent_evidence import build_candidate_record
from app.cve.agent_evidence import build_budget_usage_summary
from app.cve.agent_evidence import count_page_roles
from app.cve.agent_evidence import merge_candidate_into_state
from app.cve.agent_evidence import merge_evidence
from app.cve.agent_evidence import normalize_discovery_sources
from app.cve.agent_evidence import serialize_patch
from app.cve.agent_evidence import upsert_candidate_artifact
from app.models.cve import CVEPatchArtifact


def test_merge_evidence_preserves_discovery_sources() -> None:
    merged = merge_evidence(
        existing={
            "discovery_sources": [
                {
                    "source_url": "https://a.example/1",
                    "source_host": "a.example",
                    "discovery_rule": "matcher",
                    "source_kind": "seed",
                }
            ],
            "evidence_source_count": 1,
        },
        incoming={
            "candidate_url": "https://example.com/fix.patch",
            "discovery_sources": [
                {
                    "source_url": "https://b.example/2",
                    "source_host": "b.example",
                    "discovery_rule": "matcher",
                    "source_kind": "page",
                }
            ],
            "evidence_source_count": 1,
        },
    )

    assert merged["evidence_source_count"] == 2
    assert [source["source_url"] for source in merged["discovery_sources"]] == [
        "https://a.example/1",
        "https://b.example/2",
    ]


def test_merge_candidate_into_state_deduplicates_by_canonical_key() -> None:
    state = {"direct_candidates": []}
    first_candidate = {
        "candidate_url": "https://example.com/fix.patch",
        "candidate_type": "patch",
        "patch_type": "patch",
        "canonical_key": "patch:https://example.com/fix.patch",
        "discovered_from_url": "https://a.example/advisory",
        "discovery_sources": [
            {
                "source_url": "https://a.example/advisory",
                "source_host": "a.example",
                "discovery_rule": "matcher",
                "source_kind": "seed",
            }
        ],
    }
    second_candidate = {
        **first_candidate,
        "discovered_from_url": "https://b.example/tracker",
        "discovery_sources": [
            {
                "source_url": "https://b.example/tracker",
                "source_host": "b.example",
                "discovery_rule": "matcher",
                "source_kind": "page",
            }
        ],
    }

    merge_candidate_into_state(state, first_candidate)
    merge_candidate_into_state(state, second_candidate)

    assert len(state["direct_candidates"]) == 1
    assert state["direct_candidates"][0]["evidence_source_count"] == 2


def test_build_candidate_record_marks_bugzilla_attachment_rule() -> None:
    record = build_candidate_record(
        snapshot_url="https://bugzilla.example/show_bug.cgi?id=1",
        candidate={
            "candidate_url": "https://bugzilla.example/attachment.cgi?id=42",
            "patch_type": "bugzilla_attachment_patch",
        },
        source_kind="page",
    )

    assert record["candidate_type"] == "bugzilla_attachment_patch"
    assert record["discovery_rule"] == "bugzilla_attachment"
    assert record["discovery_sources"][0]["source_host"] == "bugzilla.example"


def test_normalize_discovery_sources_ignores_invalid_items_and_preserves_order() -> None:
    sources = normalize_discovery_sources(
        [
            {"source_url": "https://a.example/1", "source_kind": "seed"},
            {"source_url": ""},
            "invalid",
            {"discovered_from_url": "https://b.example/2", "discovery_rule": "url_fallback"},
        ]
    )

    assert sources == [
        {
            "source_url": "https://a.example/1",
            "source_host": "a.example",
            "discovery_rule": "matcher",
            "source_kind": "seed",
            "order": 0,
        },
        {
            "source_url": "https://b.example/2",
            "source_host": "b.example",
            "discovery_rule": "url_fallback",
            "source_kind": "page",
            "order": 3,
        },
    ]


def test_count_page_roles_ignores_invalid_history_entries() -> None:
    assert count_page_roles(
        {
            "page_role_history": [
                {"role": "tracker_page"},
                {"role": "tracker_page"},
                {"role": "commit_page"},
                {"role": ""},
                "invalid",
            ]
        }
    ) == {
        "tracker_page": 2,
        "commit_page": 1,
    }


def test_serialize_patch_returns_stable_patch_projection() -> None:
    patch_id = uuid.uuid4()
    patch = CVEPatchArtifact(
        patch_id=patch_id,
        run_id=uuid.uuid4(),
        candidate_url="https://example.com/fix.patch",
        patch_type="patch",
        download_status="downloaded",
        patch_meta_json={"content_type": "text/x-patch"},
    )

    assert serialize_patch(patch) == {
        "patch_id": str(patch_id),
        "candidate_url": "https://example.com/fix.patch",
        "patch_type": "patch",
        "download_status": "downloaded",
        "patch_meta_json": {"content_type": "text/x-patch"},
    }


def test_agent_nodes_keeps_private_evidence_compatibility_aliases() -> None:
    assert agent_nodes._merge_evidence(existing=None, incoming={  # noqa: SLF001
        "candidate_url": "https://example.com/fix.patch",
        "discovered_from_url": "https://example.com/advisory",
    }) == merge_evidence(
        existing=None,
        incoming={
            "candidate_url": "https://example.com/fix.patch",
            "discovered_from_url": "https://example.com/advisory",
        },
    )
    assert agent_nodes._upsert_candidate_artifact is not None  # noqa: SLF001
    assert agent_nodes.upsert_candidate_artifact is upsert_candidate_artifact
    assert agent_nodes._build_budget_usage_summary({"budget": {}}) == build_budget_usage_summary(  # noqa: SLF001
        {"budget": {}}
    )
