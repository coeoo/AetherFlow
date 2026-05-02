#!/usr/bin/env python3
"""批量端到端 UI 验收 driver。

通过 playwright-cli headless 模拟用户在前端 /patch 页面提交 CVE，
然后 polling backend API 监督 worker 完成。每个 CVE 输出 screenshot + API
响应 + summary 到 results-dir。

用法:
    .venv/bin/python backend/scripts/batch_ui_acceptance.py \
        --cve-list backend/results/linux-30cve-spec/cve_list.json \
        --results-dir backend/results/linux-30cve-headless-2026-05-02

dry-run 单 CVE:
    .venv/bin/python backend/scripts/batch_ui_acceptance.py \
        --cve CVE-2026-23401 \
        --results-dir /tmp/dry-run

前置: scripts/dev_start.sh 已启动（postgres / api / frontend / worker）
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

API_BASE = os.environ.get("AETHERFLOW_DEV_API_BASE_URL", "http://127.0.0.1:18080")
FRONTEND_BASE = os.environ.get(
    "AETHERFLOW_DEV_FRONTEND_BASE_URL", "http://127.0.0.1:5180"
)


def run_pw(*args: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    """跑 playwright-cli 子命令并返回结果。"""
    cmd = ["playwright-cli", *args]
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, check=False
    )


def find_ref(snapshot_text: str, role: str, name: str) -> str | None:
    """在 snapshot YAML 文本里找 role+name 的 ref。"""
    pattern = rf'{role} "{re.escape(name)}"\s*\[ref=([^\]]+)\]'
    m = re.search(pattern, snapshot_text)
    return m.group(1) if m else None


def find_ref_disabled_aware(
    snapshot_text: str, role: str, name: str
) -> str | None:
    """同 find_ref 但跳过 [disabled]。"""
    pattern = rf'{role} "{re.escape(name)}"(?!\s*\[disabled\])\s*\[ref=([^\]]+)\]'
    m = re.search(pattern, snapshot_text)
    return m.group(1) if m else None


def get_current_url() -> str:
    """从 playwright-cli eval 拿当前 URL。"""
    r = run_pw("eval", "() => window.location.href")
    return r.stdout.strip()


def submit_cve_via_ui(cve_id: str) -> tuple[str | None, str | None]:
    """通过 UI 提交 CVE，返回 (run_id, error)。

    UI 流程（与真实用户操作一致）：
    1. goto /patch
    2. fill 漏洞编号输入框
    3. click "开始查询"（触发历史 run 查询，URL 变 /patch?q=CVE-XXX）
    4. 等历史查询完成，"开始检索" 按钮 enable
    5. click "开始检索"（真正 createRun.mutate → POST /api/v1/cve/runs）
    6. polling GET /api/v1/cve/runs?limit=6 拿到新建 run_id
    """
    # 1. 导航到 /patch
    r = run_pw("goto", f"{FRONTEND_BASE}/patch")
    if r.returncode != 0:
        return None, f"goto failed: {r.stderr.strip()[:200]}"

    # 2. snapshot 找输入框 + "开始查询" 按钮 ref
    r = run_pw("snapshot")
    snap = r.stdout
    input_ref = find_ref(snap, "textbox", "漏洞编号")
    query_ref = find_ref_disabled_aware(snap, "button", "开始查询")
    if not input_ref:
        return None, "input ref not found in snapshot"
    if not query_ref:
        return None, "query button ref not found in snapshot"

    # 3. fill + click "开始查询"
    r = run_pw("fill", input_ref, cve_id)
    if r.returncode != 0:
        return None, f"fill failed: {r.stderr.strip()[:200]}"
    r = run_pw("click", query_ref)
    if r.returncode != 0:
        return None, f"click 开始查询 failed: {r.stderr.strip()[:200]}"

    # 4. 等历史查询完成（~1-2s），重新 snapshot 找 "开始检索" 按钮 (非 disabled)
    time.sleep(2.5)
    r = run_pw("snapshot")
    snap2 = r.stdout
    start_ref = find_ref_disabled_aware(snap2, "button", "开始检索")
    if not start_ref:
        # fallback: 已存在历史 run（如重复跑），按钮叫"重新检索"
        start_ref = find_ref_disabled_aware(snap2, "button", "重新检索")
    if not start_ref:
        return None, "开始检索/重新检索 button (non-disabled) not found"

    # 5. click "开始检索" 真正创建 run
    r = run_pw("click", start_ref)
    if r.returncode != 0:
        return None, f"click 开始检索 failed: {r.stderr.strip()[:200]}"

    # 6. polling /runs 找新建 run_id（cve_id 匹配 + status=queued|running|succeeded）
    time.sleep(2)
    deadline = time.time() + 15
    last_run = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(
                f"{API_BASE}/api/v1/cve/runs?limit=6", timeout=5
            ) as resp:
                runs_data = json.loads(resp.read())
            for r_item in runs_data.get("data") or []:
                if r_item.get("cve_id") == cve_id:
                    last_run = r_item
                    break
            if last_run:
                break
        except Exception:
            pass
        time.sleep(1)

    if not last_run or not last_run.get("run_id"):
        return None, f"run_id not found after submit (cve_id={cve_id})"
    return last_run["run_id"], None


def poll_run_until_done(
    run_id: str, timeout_sec: int = 300
) -> tuple[dict[str, Any] | None, str | None]:
    """polling API 直到 run.status in (succeeded, failed)。"""
    deadline = time.time() + timeout_sec
    last_status: str | None = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(
                f"{API_BASE}/api/v1/cve/runs/{run_id}", timeout=10
            ) as resp:
                payload = json.loads(resp.read())
            data = payload.get("data") or {}
            status = data.get("status")
            last_status = status
            if status in ("succeeded", "failed"):
                return data, None
        except Exception:
            pass
        time.sleep(5)
    return None, f"polling_timeout (last_status={last_status})"


def extract_patch_summary(data: dict[str, Any]) -> dict[str, Any]:
    """从 GET /runs/{id} 响应中提取 patch 摘要。"""
    summary = data.get("summary") or {}
    progress = data.get("progress") or {}
    patches = progress.get("patches") or []
    downloaded = [
        p
        for p in patches
        if str(p.get("download_status") or p.get("status") or "") == "downloaded"
    ]
    return {
        "status": data.get("status"),
        "stop_reason": data.get("stop_reason") or summary.get("stop_reason"),
        "patch_found": bool(downloaded) or bool(summary.get("patch_found")),
        "patch_count": len(downloaded) or int(summary.get("patch_count") or 0),
        "patch_urls": [
            p.get("candidate_url") or p.get("patch_url") for p in downloaded
        ][:10],
        "runtime_kind": summary.get("runtime_kind"),
        "phase": data.get("phase"),
    }


def write_progress(progress_path: Path, progress: dict) -> None:
    progress_path.write_text(
        json.dumps(progress, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cve-list", help="cve_list.json 路径")
    parser.add_argument("--cve", help="单 CVE dry-run（覆盖 --cve-list）")
    parser.add_argument("--results-dir", required=True)
    parser.add_argument("--timeout-per-cve", type=int, default=300)
    parser.add_argument("--start-from", type=int, default=1, help="从第 N 个 CVE 开始（断点续跑）")
    args = parser.parse_args()

    if not args.cve and not args.cve_list:
        parser.error("必须提供 --cve 或 --cve-list 之一")

    results_dir = Path(args.results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)

    if args.cve:
        cves: list[dict[str, Any]] = [
            {"cve_id": args.cve, "category": "dry-run", "package": "?"}
        ]
    else:
        with open(args.cve_list, encoding="utf-8") as f:
            cves = json.load(f)["cves"]

    progress_path = results_dir / "batch_progress.json"
    progress = {
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "total": len(cves),
        "items": [],
    }

    for idx, cve_meta in enumerate(cves, 1):
        if idx < args.start_from:
            continue
        cve_id = cve_meta["cve_id"]
        cat = cve_meta.get("category", "?")
        pkg = cve_meta.get("package", "?")
        print(f"[{idx}/{len(cves)}] {cve_id} ({cat}/{pkg})", flush=True)

        t0 = time.time()
        run_id, err = submit_cve_via_ui(cve_id)
        if err:
            entry = {**cve_meta, "step": "submit", "error": err, "duration_s": round(time.time() - t0, 1)}
            progress["items"].append(entry)
            print(f"  ✗ submit failed: {err}", flush=True)
            write_progress(progress_path, progress)
            continue
        print(f"  → run_id={run_id}", flush=True)

        run_data, perr = poll_run_until_done(run_id, args.timeout_per_cve)
        dur = time.time() - t0
        if perr or run_data is None:
            entry = {
                **cve_meta,
                "run_id": run_id,
                "step": "poll",
                "error": perr or "no_data",
                "duration_s": round(dur, 1),
            }
            progress["items"].append(entry)
            print(f"  ✗ {perr} ({dur:.0f}s)", flush=True)
            write_progress(progress_path, progress)
            continue

        cve_dir = results_dir / cve_id.lower().replace("/", "-")
        cve_dir.mkdir(parents=True, exist_ok=True)

        # 截图详情页（playwright 当前可能仍在 /patch，先 goto 详情页）
        detail_url = f"{FRONTEND_BASE}/cve/runs/{run_id}"
        run_pw("goto", detail_url, timeout=30)
        time.sleep(2)
        run_pw("screenshot", str(cve_dir / "detail.png"), timeout=30)

        # 写 API 完整响应
        (cve_dir / "api_response.json").write_text(
            json.dumps(run_data, ensure_ascii=False, indent=2), encoding="utf-8"
        )

        summary = extract_patch_summary(run_data)
        entry = {
            **cve_meta,
            "run_id": run_id,
            "step": "done",
            "duration_s": round(dur, 1),
            **summary,
        }
        progress["items"].append(entry)
        print(
            f"  ✓ {summary['status']:9} found={summary['patch_found']!s:5} "
            f"patches={summary['patch_count']} dur={dur:.0f}s reason={summary['stop_reason']}",
            flush=True,
        )
        write_progress(progress_path, progress)

    progress["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    write_progress(progress_path, progress)

    done = [i for i in progress["items"] if i.get("step") == "done"]
    found = [i for i in done if i.get("patch_found")]
    print()
    print("=" * 60)
    print(
        f"Summary: {len(done)}/{len(cves)} 完成, "
        f"patch_found={len(found)}/{len(done)} ({100 * len(found) / max(len(done), 1):.1f}%)"
    )
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
