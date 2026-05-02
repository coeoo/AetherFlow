# Journal - coeoo (Part 1)

> AI development session journal
> Started: 2026-04-29

---

## Session 1: Phase C Step 1 — candidate_generator reference_url normalize-before-match

**Date**: 2026-05-02
**Task**: 05-01-phase-c-seed-fast-path (Step 1 of 7)
**Branch**: `main`

### Summary

落地 Phase C 入口前置 normalize_frontier_url；诊断阶段反转 phase-b4 的"反向退化"归因——真因是 patch_downloader 真实网络下载 flake，与 normalize 无关。

### Main Changes

- `backend/app/cve/candidate_generator.py`: reference_url 分支 `target_url = normalize_frontier_url(ev.url) or ev.url`；删除 phase-b4 Q7 占位注释（6 行）；docstring 同步；局部 import 沿用 canonical 同款延迟模式
- `backend/tests/test_candidate_generator.py`: 加 fragment / 多余空白 / openwall http→https 三类 normalize 边界用例

### Diagnostic Findings (推翻 phase-b4 归因)

phase-b4 commit `bd05f30` 当时记录"normalize 后 CVE-2022-2509 mock-mode 反向退化（patches=0）"，未定位根因即回退保护 baseline。本会话重新跑 ON/OFF 各 ≥5 次 acceptance 发现：

- OFF 模式（normalize 关）也以 ~37% 概率丢同一 `merge_requests/1615.patch`
- navigation_path / search_nodes_count / failed_attempts 在 ON/OFF 间完全相同
- 真因：`patch_downloader.py:420` 用 `http_client.get` 真实网络下载 gitlab.com / github.com 的 patch URL，存在网络抖动 / 限流 flake
- phase-b4 当时把单次 flake 归因为 normalize 是误判

### Git Commits

| Hash | Message |
|------|---------|
| `f84664f` | 重构(cve): candidate_generator reference_url 路径补 normalize-before-match |

### Testing

- [OK] pytest 5 文件 (test_cve_agent_graph + test_candidate_generator + test_candidate_scoring + test_reference_matcher + test_seed_resolver_enriched) => 162 passed in 21.97s（159 baseline + 3 新增）
- [OK] mock-mode acceptance（rule-fallback-only profile）: CVE-2022-2509 / CVE-2024-3094 双 PASS, patch_found=true
- [OK] 真实样本 acceptance（dashscope-stable profile + .env.local LLM）: CVE-2022-2509 PASS dur=62.4s / CVE-2024-3094 PASS dur=105.1s

### Status

[OK] **Completed** — Step 1 落地

### Follow-up

- patch_downloader 真实网络下载 flake（`http_client.get` 拉 gitlab.com / github.com） — 立独立任务跟踪，影响所有 mock-mode acceptance 的可重复性
- Step 2: acceptance script 扩 CVE-2024-38545 scenario
- Step 3+: feature flag + validate_seed_candidates_node 主体实现

### Next Steps

- 进入 Phase C Step 2（PRD `.trellis/tasks/05-01-phase-c-seed-fast-path/prd.md` 已收敛）
- 决定是否在 Phase C 内顺手修 patch_downloader mock-mode 真实网络问题，或独立任务

---
