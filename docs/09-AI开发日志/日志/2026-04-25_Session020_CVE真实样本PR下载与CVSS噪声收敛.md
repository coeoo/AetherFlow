# 2026-04-25 Session020 - CVE 真实样本 PR 下载与 CVSS 噪声收敛

## 状态

✅ 已完成

## 本次目标

继续收敛 CVE Patch Agent 的真实样本验收结果，优先处理 20 个新增真实 CVE 样本中暴露的 P0/P1 问题，而不是继续盲目扩展下载来源。

本轮聚焦两类真实失败：

1. GitHub PR `.patch` 下载短时 timeout 后没有 fallback。
2. NVD CVSS calculator 被当作普通 advisory frontier 消耗页面和 LLM 预算。

## 做了什么

- 汇总子代理和本地主线程的只读分析结果，确认：
  - `CVE-2025-69413` 与 `CVE-2026-5271` 都已找到 GitHub PR patch 候选；
  - 失败发生在 downloader 阶段，`failed_patch_types=["github_pull_patch"]`，`patch_failure_kinds=["timeout"]`；
  - 这不是 LLM 导航问题，也不是候选抽取问题。
- 按 TDD 补充 `github_pull_patch` fallback 测试，先验证红灯，再实现最小修复。
- 为 GitHub PR 候选增加 Pull API patch / diff 与页面 `.diff` fallback。
- 分析 `CVE-2026-0544`、`CVE-2025-15404`、`CVE-2025-15406` 的旧报告和 LLM 日志，确认：
  - LLM 已判断 CVSS calculator 没有补丁线索；
  - 实际误走来自 frontier / rule fallback 继续选择 `/vuln-metrics/cvss/`；
  - 根因不是 LLM 误判，而是导航噪声过滤缺口。
- 按 TDD 增加 NVD CVSS calculator 过滤测试，覆盖页面抽链和历史 frontier fallback 两条入口。
- 将 `/vuln-metrics/cvss/` 加入全局导航噪声路径。
- 更新功能设计、收敛方案和 AI 接手说明。

## 更新代码

- `backend/app/cve/patch_downloader.py`
  - 新增 GitHub PR URL 识别。
  - 新增 GitHub PR fallback 策略：页面 `.patch` → Pull API patch → Pull API diff → 页面 `.diff`。
  - 保持 `GITHUB_TOKEN` 仅从环境变量读取，无 token 时仍可匿名调用 GitHub API。
- `backend/app/cve/agent_nodes.py`
  - 将 NVD CVSS calculator 路径 `/vuln-metrics/cvss/` 归入全局导航噪声。
- `backend/tests/test_patch_downloader.py`
  - 新增 PR `.patch` timeout 后 fallback 到 GitHub Pull API diff 的回归测试。
- `backend/tests/test_cve_agent_graph.py`
  - 新增页面抽链过滤 NVD CVSS calculator 的测试。
  - 新增规则 fallback 跳过历史 frontier 中 NVD CVSS calculator 的测试。

## 更新文档

- `docs/04-功能设计/M103-CVE数据源与页面探索规则功能设计.md`
  - 补充 GitHub PR 多策略下载。
  - 补充 NVD CVSS calculator 噪声过滤规则。
  - 补充本轮真实失败根因。
- `docs/superpowers/specs/2026-04-24-cve-real-sample-convergence-design.md`
  - 更新 20 CVE 真实样本收敛结论。
  - 记录 P0/P1 已完成项和后续非维护范围组件跳过机制。
- `docs/09-AI开发日志/README_AI使用说明.md`
  - 更新 CVE Patch Agent 接手要点和版本记录。
- `docs/09-AI开发日志/日志/2026-04-25_Session020_CVE真实样本PR下载与CVSS噪声收敛.md`
  - 新增本次开发日志。

## 关键决策

- 不继续盲目扩展新下载源，先根据真实样本证据修复已确认的失败模式。
- `github_pull_patch` 仍保留页面 `.patch` 为第一策略，避免改变既有成功路径；只在失败后进入 API / `.diff` fallback。
- GitHub token 仍是可选稳定性增强，不作为 API 路径前置条件。
- NVD CVSS calculator 是评分工具页，不是补丁、tracker、commit 或 download 线索；应在 frontier 和 fallback 层过滤。
- WordPress、WPScan、Trac 插件等非当前维护范围组件不应默认推动 downloader 扩源，后续应增加维护范围/行动项判断。

## 验证结果

单元与图节点回归：

- `timeout 60s ./.venv/bin/python -m pytest backend/tests/test_patch_downloader.py -q`
  - 结果：`7 passed, 5 skipped`
- `timeout 60s ./.venv/bin/python -m pytest backend/tests/test_cve_agent_graph.py -q`
  - 结果：`28 passed, 35 skipped`
- PR 下载相关联动回归：
  - 结果：`37 passed, 1 skipped`

真实复测：

- `CVE-2025-69413`
  - 旧结果：`patch_download_failed / timeout`
  - 新结果：`succeeded / PASS / patches_downloaded`
  - patch：`https://github.com/go-gitea/gitea/pull/36002.patch`
- `CVE-2026-5271`
  - 旧结果：`patch_download_failed / timeout`
  - 新结果：`succeeded / PASS / patches_downloaded`
  - patch：`https://github.com/python/pymanager/pull/301.patch`
- `CVE-2026-0544`
  - 新结果：不再进入 `/vuln-metrics/cvss/`
  - 当前仍为 `no_patch_candidates`，失败原因已从 CVSS 预算浪费收敛为无补丁候选。

## 下次计划

- 增加非维护范围组件跳过机制，优先覆盖 WordPress、WPScan、Trac 插件等样本。
- 调整验收语义，区分系统失败、可接受的无公开补丁、非维护范围跳过。
- 必要时继续复测 `CVE-2025-15404` 与 `CVE-2025-15406`，确认 CVSS 噪声过滤对同类样本稳定生效。
- 在形成明确失败证据后，再决定是否扩展更多来源站点下载策略。
