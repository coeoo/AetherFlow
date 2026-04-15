from pathlib import Path

import pytest

from app.cve.page_analyzer import analyze_page


FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "cve_regressions"


def _load_fixture(name: str) -> str:
    return (FIXTURE_DIR / name).read_text(encoding="utf-8")


@pytest.fixture(autouse=True)
def _forbid_network(monkeypatch) -> None:
    def _fail(*args, **kwargs):
        raise AssertionError("regression fixture 测试不允许访问真实网络")

    monkeypatch.setattr("httpx.get", _fail)


def test_regression_debian_bts_page_hits_debdiff_candidate() -> None:
    candidates = analyze_page(
        {
            "url": "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=848132",
            "content": _load_fixture("cve_2016_1253_debian_bts_bugreport.html"),
        }
    )

    assert candidates == [
        {
            "candidate_url": "https://bugs.debian.org/cgi-bin/bugreport.cgi?att=1;bug=848132;filename=most.debdiff;msg=5",
            "patch_type": "debdiff",
        }
    ]


def test_regression_bugzilla_page_hits_raw_attachment_candidate() -> None:
    candidates = analyze_page(
        {
            "url": "https://bugzilla.redhat.com/show_bug.cgi?id=832532",
            "content": _load_fixture("cve_2012_2737_bugzilla_redhat_832532.html"),
        }
    )

    assert candidates == [
        {
            "candidate_url": "https://bugzilla.redhat.com/attachment.cgi?id=593003",
            "patch_type": "bugzilla_attachment_patch",
        }
    ]


def test_regression_openwall_page_hits_github_commit_patch_candidate() -> None:
    candidates = analyze_page(
        {
            "url": "https://www.openwall.com/lists/oss-security/2024/03/29/4",
            "content": _load_fixture("cve_2024_3094_openwall_oss_security_2024_03_29_4.html"),
        }
    )

    assert candidates == [
        {
            "candidate_url": "https://github.com/tukaani-project/xz/commit/cf44e4b7f5dfdbf8c78aef377c10f71e274f63c0.patch",
            "patch_type": "github_commit_patch",
        },
        {
            "candidate_url": "https://github.com/tukaani-project/xz/commit/e5faaebbcf02ea880cfc56edc702d4f7298788ad.patch",
            "patch_type": "github_commit_patch",
        },
        {
            "candidate_url": "https://github.com/tukaani-project/xz/commit/72d2933bfae514e0dbb123488e9f1eb7cf64175f.patch",
            "patch_type": "github_commit_patch",
        },
        {
            "candidate_url": "https://github.com/tukaani-project/xz/commit/82ecc538193b380a21622aea02b0ba078e7ade92.patch",
            "patch_type": "github_commit_patch",
        },
        {
            "candidate_url": "https://github.com/tukaani-project/xz/commit/6e636819e8f070330d835fce46289a3ff72a7b89.patch",
            "patch_type": "github_commit_patch",
        },
    ]
