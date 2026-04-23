from __future__ import annotations

import argparse
import json
from pathlib import Path

from scripts import acceptance_browser_agent as acceptance_module
from scripts.acceptance_browser_agent import _compare_acceptance_reports


DEFAULT_BASELINE_REPORT_PATH = (
    Path(__file__).resolve().parents[1]
    / "tests"
    / "fixtures"
    / "browser_agent"
    / "acceptance_baselines"
    / "rule_fallback_gate_baseline.json"
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m scripts.acceptance_regression_gate",
        description="运行本地稳定 acceptance 回归门禁。",
    )
    parser.add_argument(
        "--baseline-report",
        default=str(DEFAULT_BASELINE_REPORT_PATH),
        help="基线 acceptance_report.json 路径。",
    )
    parser.add_argument(
        "--candidate-report",
        default=None,
        help="候选 acceptance_report.json 路径；未提供时由脚本生成。",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="可选，写出 gate 结果 JSON。",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    baseline_report = _load_baseline_report(Path(args.baseline_report))
    candidate_report_path = (
        Path(args.candidate_report)
        if args.candidate_report
        else _generate_candidate_report(args)
    )
    candidate_report = _load_baseline_report(candidate_report_path)
    comparison = _compare_acceptance_reports(baseline_report, candidate_report)
    gate_result = _evaluate_gate_result(comparison)
    payload = {
        **gate_result,
        "baseline_report": str(Path(args.baseline_report)),
        "candidate_report": str(candidate_report_path),
        "comparison": comparison,
    }
    rendered = json.dumps(payload, ensure_ascii=False, indent=2)
    print(rendered)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    return int(payload["exit_code"])


def _load_baseline_report(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _generate_candidate_report(args: argparse.Namespace) -> Path:
    output_dir = Path(args.output).resolve().parent if args.output else Path.cwd()
    results_dir = output_dir / ".acceptance-gate"
    results_dir.mkdir(parents=True, exist_ok=True)
    exit_code = acceptance_module.main(
        [
            "--cve",
            "CVE-2022-2509",
            "--profile",
            "rule-fallback-only",
            "--mock-mode",
            "llm-timeout-forced",
            "--results-dir",
            str(results_dir),
        ]
    )
    if exit_code != 0:
        raise RuntimeError(f"生成 candidate acceptance report 失败: exit_code={exit_code}")
    return results_dir / "acceptance_report.json"


def _evaluate_gate_result(comparison: dict[str, object]) -> dict[str, object]:
    failures: list[dict[str, object]] = []
    warnings: list[dict[str, object]] = []

    for scenario_diff in list(comparison.get("scenario_diffs") or []):
        if not isinstance(scenario_diff, dict):
            continue
        cve_id = str(scenario_diff.get("cve_id") or "")
        signals = dict(scenario_diff.get("signals") or {})

        if bool(signals.get("patch_quality_degraded")):
            failures.append({"cve_id": cve_id, "signal": "patch_quality_degraded"})
        if bool(signals.get("high_value_path_regressed")):
            failures.append({"cve_id": cve_id, "signal": "high_value_path_regressed"})

        if bool(signals.get("patch_url_changed")):
            warnings.append({"cve_id": cve_id, "signal": "patch_url_changed"})
        if bool(signals.get("navigation_path_changed")):
            warnings.append({"cve_id": cve_id, "signal": "navigation_path_changed"})
        if bool(signals.get("more_rule_fallback")):
            warnings.append({"cve_id": cve_id, "signal": "more_rule_fallback"})
        new_page_roles = list(signals.get("new_page_roles") or [])
        if new_page_roles:
            warnings.append(
                {
                    "cve_id": cve_id,
                    "signal": "new_page_roles",
                    "roles": [str(role) for role in new_page_roles],
                }
            )

    return {
        "passed": not failures,
        "exit_code": 0 if not failures else 1,
        "failures": failures,
        "warnings": warnings,
    }
