"""Tests for enriched extraction from seed sources."""
import httpx

from app.cve.seed_sources import (
    FixCommitEvidence,
    FixedVersionEvidence,
    StructuredReference,
    fetch_seed_source,
    _extract_cve_official_enriched,
    _extract_osv_enriched,
    _extract_github_advisory_enriched,
    _extract_nvd_enriched,
)


def _make_response(*, url: str, status_code: int, json_data=None) -> httpx.Response:
    request = httpx.Request("GET", url)
    return httpx.Response(status_code, json=json_data, request=request)


# ── CVE Official enriched ──────────────────────────────────────────────


def test_cve_official_enriched_extracts_tags_and_adp() -> None:
    payload = {
        "containers": {
            "cna": {
                "references": [
                    {"url": "https://example.com/patch", "tags": ["patch", "vendor-advisory"]},
                    {"url": "https://example.com/advisory"},
                ],
            },
            "adp": [
                {
                    "references": [
                        {"url": "https://example.com/adp-ref", "tags": ["third-party-advisory"]},
                    ]
                }
            ],
        }
    }
    result = _extract_cve_official_enriched(payload)
    assert len(result.references) == 3
    assert len(result.structured_references) == 3

    patch_ref = result.structured_references[0]
    assert patch_ref.url == "https://example.com/patch"
    assert patch_ref.tags == ("patch", "vendor-advisory")
    assert patch_ref.source == "cve_official"

    adp_ref = result.structured_references[2]
    assert adp_ref.url == "https://example.com/adp-ref"
    assert adp_ref.tags == ("third-party-advisory",)


def test_cve_official_enriched_extracts_git_fix_commits() -> None:
    payload = {
        "containers": {
            "cna": {
                "references": [],
                "affected": [
                    {
                        "versions": [
                            {"versionType": "git", "lessThan": "abc123def456"},
                            {"versionType": "semver", "lessThan": "1.2.3"},
                        ]
                    }
                ],
            }
        }
    }
    result = _extract_cve_official_enriched(payload)
    assert len(result.fix_commits) == 1
    assert result.fix_commits[0].commit_sha == "abc123def456"
    assert result.fix_commits[0].source == "cve_official"
    assert result.fixed_versions == []


# ── OSV enriched ───────────────────────────────────────────────────────


def test_osv_enriched_extracts_ref_types_and_fix_commits() -> None:
    payload = {
        "references": [
            {"url": "https://example.com/advisory", "type": "ADVISORY"},
            {"url": "https://example.com/fix", "type": "FIX"},
        ],
        "affected": [
            {
                "package": {"name": "linux", "ecosystem": "Linux"},
                "ranges": [
                    {
                        "type": "GIT",
                        "repo": "https://github.com/torvalds/linux",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "deadbeef1234"},
                        ],
                    },
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "5.15.1"},
                        ],
                    },
                ],
            }
        ],
    }
    result = _extract_osv_enriched(payload)

    assert len(result.structured_references) == 2
    assert result.structured_references[0].ref_type == "ADVISORY"
    assert result.structured_references[1].ref_type == "FIX"

    assert len(result.fix_commits) == 1
    assert result.fix_commits[0].commit_sha == "deadbeef1234"
    assert result.fix_commits[0].repo_hint == "https://github.com/torvalds/linux"

    assert len(result.fixed_versions) == 1
    assert result.fixed_versions[0].version == "5.15.1"
    assert result.fixed_versions[0].package_name == "linux"
    assert result.fixed_versions[0].package_ecosystem == "Linux"


# ── GitHub Advisory enriched ──────────────────────────────────────────


def test_github_advisory_enriched_extracts_fixed_versions() -> None:
    payload = [
        {
            "html_url": "https://github.com/advisories/GHSA-1234",
            "references": ["https://example.com/ref"],
            "source_code_location": "https://github.com/owner/repo",
            "vulnerabilities": [
                {
                    "package": {"name": "my-pkg", "ecosystem": "npm"},
                    "first_patched_version": "2.0.1",
                }
            ],
        }
    ]
    result = _extract_github_advisory_enriched(payload)

    assert len(result.references) == 2
    assert result.structured_references[0].ref_type == "ADVISORY"
    assert result.structured_references[0].url == "https://github.com/advisories/GHSA-1234"

    assert len(result.fixed_versions) == 1
    fv = result.fixed_versions[0]
    assert fv.version == "2.0.1"
    assert fv.package_name == "my-pkg"
    assert fv.package_ecosystem == "npm"
    assert fv.repo_hint == "https://github.com/owner/repo"


# ── NVD enriched ──────────────────────────────────────────────────────


def test_nvd_enriched_extracts_tags() -> None:
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "references": [
                        {"url": "https://example.com/patch", "tags": ["Patch", "Third Party Advisory"]},
                        {"url": "https://example.com/info"},
                    ]
                }
            }
        ]
    }
    result = _extract_nvd_enriched(payload)
    assert len(result.structured_references) == 2
    assert result.structured_references[0].tags == ("Patch", "Third Party Advisory")
    assert result.structured_references[0].source == "nvd"
    assert result.structured_references[1].tags == ()


# ── Integration: fetch_seed_source passes enriched data ───────────────


def test_fetch_cve_official_passes_enriched_data(monkeypatch) -> None:
    cve_id = "CVE-2024-0001"
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"

    def _fake_get(got_url, **kwargs):
        return _make_response(
            url=got_url,
            status_code=200,
            json_data={
                "containers": {
                    "cna": {
                        "references": [
                            {"url": "https://github.com/owner/repo/commit/abc123", "tags": ["patch"]},
                        ],
                        "affected": [
                            {"versions": [{"versionType": "git", "lessThan": "abc123"}]}
                        ],
                    }
                }
            },
        )

    monkeypatch.setattr("app.cve.seed_sources.http_client.get", _fake_get)
    result = fetch_seed_source("cve_official", cve_id=cve_id)

    assert result.status == "success"
    assert len(result.structured_references) == 1
    assert result.structured_references[0].tags == ("patch",)
    assert len(result.fix_commits) == 1
    assert result.fix_commits[0].commit_sha == "abc123"


def test_fetch_osv_passes_enriched_data(monkeypatch) -> None:
    cve_id = "CVE-2024-0002"
    url = f"https://api.osv.dev/v1/vulns/{cve_id}"

    def _fake_get(got_url, **kwargs):
        return _make_response(
            url=got_url,
            status_code=200,
            json_data={
                "references": [{"url": "https://example.com/fix", "type": "FIX"}],
                "affected": [
                    {
                        "package": {"name": "pkg", "ecosystem": "PyPI"},
                        "ranges": [
                            {
                                "type": "GIT",
                                "repo": "https://github.com/owner/repo",
                                "events": [{"fixed": "deadbeef"}],
                            }
                        ],
                    }
                ],
            },
        )

    monkeypatch.setattr("app.cve.seed_sources.http_client.get", _fake_get)
    result = fetch_seed_source("osv", cve_id=cve_id)

    assert result.status == "success"
    assert len(result.structured_references) == 1
    assert result.structured_references[0].ref_type == "FIX"
    assert len(result.fix_commits) == 1
    assert result.fix_commits[0].commit_sha == "deadbeef"
    assert result.fix_commits[0].repo_hint == "https://github.com/owner/repo"
