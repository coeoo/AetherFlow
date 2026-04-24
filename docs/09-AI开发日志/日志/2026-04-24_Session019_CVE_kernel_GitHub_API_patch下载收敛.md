# 2026-04-24 Session019 - CVE kernel GitHub API patch 下载收敛

## 状态

✅ 已完成

## 本次目标

验证并收敛 CVE Patch Agent 获取 kernel patch 的真实可行路径，解决 `git.kernel.org` 页面 patch 在真实网络环境中受反爬挑战和短时网络失败影响的问题。

## 做了什么

- 通过并行分析拆分 GitHub 下载、kernel 下载、历史备份实现、真实样本验收几个方向，最终统一收敛到后端下载路径。
- 确认根因不是单纯“缺浏览器头”，而是：
  - `git.kernel.org` 页面 patch 可能遇到 Anubis / bot challenge；
  - GitHub 匿名 API 可能限流；
  - 页面 `.patch` / `.diff` 链路存在短时网络失败；
  - 同一候选重复下载会放大失败概率。
- 将 kernel commit 候选下载主路径调整为：
  - 从 `git.kernel.org` commit URL 提取 commit SHA；
  - 优先尝试 GitHub API patch / diff；
  - 根据 stable hint 优先选择 `stable/linux` 或 `torvalds/linux`；
  - 将 `git.kernel.org` 直连 patch 保留为最后诊断兜底。
- 保留 `GITHUB_TOKEN` 为可选稳定性增强；token 仅从环境变量读取，不写入代码、文档或日志。
- 增强下载与运行时观测：记录每次 attempt 的 strategy、repository、media_type、status、error_kind 和节点耗时。
- 增强 acceptance 报告中的失败诊断字段，便于从真实结果反推下载失败原因。

## 更新代码

- `backend/app/cve/patch_downloader.py`
  - 增加 GitHub API patch / diff 下载策略。
  - 增加 kernel commit SHA 识别与 stable/torvalds 仓库策略切换。
  - 增加 Anubis / bot challenge 分类与 attempts 诊断字段。
- `backend/app/cve/agent_nodes.py`
  - 跳过 `downloaded` / `failed` 终态候选，避免重复下载。
  - 补强 blocked / empty 页面识别和规则 fallback。
- `backend/app/cve/canonical.py`
  - 折叠空 path segment，避免等价 patch URL 生成不同 canonical key。
- `backend/app/cve/runtime.py`
  - 增加诊断模式节点耗时与状态摘要输出。
- `backend/scripts/acceptance_browser_agent.py`
  - 报告补充失败 patch 类型、失败分类和 attempt 摘要。
- `backend/tests/*`
  - 补充 GitHub API、kernel 下载、canonical、图节点终态跳过和诊断输出回归测试。

## 更新文档

- `docs/04-功能设计/M103-CVE数据源与页面探索规则功能设计.md`
- `docs/09-AI开发日志/README_AI使用说明.md`
- `docs/09-AI开发日志/日志/2026-04-24_Session019_CVE_kernel_GitHub_API_patch下载收敛.md`

## 关键决策

- 不尝试绕过 `git.kernel.org` 的 Anubis / bot challenge；只做失败分类和诊断记录。
- kernel patch 主路径使用 commit identity 到 GitHub API 的确定性转换，减少页面反爬和页面渲染不确定性。
- `GITHUB_TOKEN` 作为推荐配置，但不能成为系统可用性的硬依赖。
- 下载链路必须以 attempts 形式保留可审计证据，便于真实 CVE 样本验收时解释失败路径。

## 验证结果

- 关键回归测试：`133 passed`。
- 真实样本：`CVE-2024-46701` 使用 `LLM_DEFAULT_MODEL=qwen3.6-flash` 复测通过。
- 真实样本结果：`status=succeeded`，`stop_reason=patches_downloaded`，`verdict=PASS`。
- 关键现象：`stable/linux` API patch 返回 404 后，自动切换到 `torvalds/linux` API patch 并下载成功。

## 下次计划

- 基于 `backend/results/` 继续汇总更多真实 CVE 样本验收结论。
- 扩展非 GitHub / 非 kernel 来源站点的补丁下载策略。
- 继续优化 LLM 决策收敛，减少无效页面跳转和重复候选。
