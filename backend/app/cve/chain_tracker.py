from __future__ import annotations

from dataclasses import asdict
from dataclasses import dataclass
from dataclasses import field
from uuid import uuid4


CHAIN_TYPE_EXPECTATIONS = {
    "advisory_to_patch": {
        "advisory_page": [
            "tracker_page",
            "commit_page",
            "pull_request_page",
            "merge_request_page",
            "download_page",
        ],
        "tracker_page": [
            "commit_page",
            "pull_request_page",
            "merge_request_page",
            "download_page",
        ],
        "commit_page": ["download_page"],
        "pull_request_page": ["download_page"],
        "merge_request_page": ["download_page"],
    },
    "tracker_to_commit": {
        "tracker_page": [
            "commit_page",
            "pull_request_page",
            "merge_request_page",
            "download_page",
        ],
        "commit_page": ["download_page"],
        "pull_request_page": ["download_page"],
        "merge_request_page": ["download_page"],
    },
    "mailing_list_to_fix": {
        "mailing_list_page": [
            "commit_page",
            "pull_request_page",
            "merge_request_page",
            "download_page",
        ],
        "commit_page": ["download_page"],
        "pull_request_page": ["download_page"],
        "merge_request_page": ["download_page"],
    },
}
DEFAULT_MAX_CHAINS = 5


@dataclass
class ChainStep:
    url: str
    page_role: str
    depth: int


@dataclass
class NavigationChain:
    chain_id: str
    chain_type: str
    steps: list[ChainStep] = field(default_factory=list)
    status: str = "in_progress"
    expected_next_roles: list[str] = field(default_factory=list)


class ChainTracker:
    """管理一次 run 中所有 NavigationChain 的生命周期。"""

    def __init__(self) -> None:
        self._chains: dict[str, NavigationChain] = {}

    def create_chain(
        self,
        *,
        chain_type: str,
        initial_url: str,
        page_role: str,
        depth: int = 0,
        max_chains: int = DEFAULT_MAX_CHAINS,
    ) -> NavigationChain:
        if len(self._chains) >= max_chains:
            raise ValueError("max_chains_exceeded")
        chain = NavigationChain(
            chain_id=f"chain-{uuid4()}",
            chain_type=chain_type,
            steps=[ChainStep(url=initial_url, page_role=page_role, depth=depth)],
            expected_next_roles=_expected_next_roles(chain_type=chain_type, page_role=page_role),
        )
        self._chains[chain.chain_id] = chain
        return chain

    def extend_chain(self, chain_id: str, *, url: str, page_role: str, depth: int) -> None:
        chain = self._require_chain(chain_id)
        chain.steps.append(ChainStep(url=url, page_role=page_role, depth=depth))
        chain.expected_next_roles = _expected_next_roles(
            chain_type=chain.chain_type,
            page_role=page_role,
        )

    def complete_chain(self, chain_id: str) -> None:
        chain = self._require_chain(chain_id)
        chain.status = "completed"
        chain.expected_next_roles = []

    def mark_dead_end(self, chain_id: str) -> None:
        chain = self._require_chain(chain_id)
        chain.status = "dead_end"
        chain.expected_next_roles = []

    def get_active_chains(self) -> list[NavigationChain]:
        return [chain for chain in self._chains.values() if chain.status == "in_progress"]

    def get_all_chains(self) -> list[NavigationChain]:
        return list(self._chains.values())

    def to_dict_list(self) -> list[dict]:
        return [asdict(chain) for chain in self._chains.values()]

    @classmethod
    def from_dict_list(cls, data: list[dict]) -> ChainTracker:
        tracker = cls()
        for item in data:
            steps = [
                ChainStep(
                    url=str(step.get("url", "")),
                    page_role=str(step.get("page_role", "")),
                    depth=int(step.get("depth", 0)),
                )
                for step in list(item.get("steps", []))
                if isinstance(step, dict)
            ]
            chain = NavigationChain(
                chain_id=str(item.get("chain_id", "")),
                chain_type=str(item.get("chain_type", "")),
                steps=steps,
                status=str(item.get("status", "in_progress")),
                expected_next_roles=[
                    str(role)
                    for role in list(item.get("expected_next_roles", []))
                ],
            )
            tracker._chains[chain.chain_id] = chain
        return tracker

    def _require_chain(self, chain_id: str) -> NavigationChain:
        if chain_id not in self._chains:
            raise KeyError(f"unknown_chain_id:{chain_id}")
        return self._chains[chain_id]


def _expected_next_roles(*, chain_type: str, page_role: str) -> list[str]:
    chain_expectations = CHAIN_TYPE_EXPECTATIONS.get(chain_type, {})
    return list(chain_expectations.get(page_role, []))
