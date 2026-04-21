# 2026-04-21 Session016 - CVE 浏览器 Agent 重设计 Phase 1-4

状态: ✅ 已完成

## 做了什么

将 CVE Patch Agent 从 **httpx 文本抓取 + 规则打分 + 局部 LLM 策略器** 重设计为 **Playwright 浏览器驱动型 AI Agent**，分 4 个 Phase 完成：

### Phase 1：浏览器基础设施
- 新增 `browser/` 包（base.py, playwright_backend.py, sync_bridge.py, a11y_pruner.py, page_role_classifier.py, markdown_extractor.py）
- 定义 `BrowserPageSnapshot` / `PageLink` / `BrowserBackend` Protocol
- 实现 `PlaywrightPool`（BrowserContext 池化）和 `SyncBrowserBridge`（async→sync 桥接）
- `config.py` 新增 5 项浏览器配置（backend、pool_size、headless、timeout_ms、cdp_endpoint）
- `pyproject.toml` 新增 playwright>=1.40 和 langgraph>=0.2 依赖

### Phase 2：LLM 接口 + 链路追踪
- 新增 `browser_agent_llm.py`（LLMPageView、NavigationContext、call_browser_agent_navigation）
- 新增 `chain_tracker.py`（ChainTracker 管理 NavigationChain 生命周期）
- 新增 `prompts/browser_agent_navigation.md`（结构化导航提示词）
- `agent_state.py` 扩展完整字段（browser_snapshots、navigation_chains、page_role_history 等）

### Phase 3：节点重写 + 图改造 + 废弃清扫
- `agent_nodes.py` 全部节点重写（~1140 行），接入浏览器快照和链路感知 LLM
- `agent_graph.py` 增加 download_and_validate 条件出边（活跃链路时回到 fetch）
- `agent_policy.py` 实现链路感知停止条件 + 新预算体系
- `runtime.py` 精简为 ~72 行单路径（SyncBrowserBridge → graph.invoke）
- `service.py` job_type 统一为 `cve_patch_agent_graph`
- 删除 5 个废弃生产文件：agent_llm.py、llm_fallback.py、page_fetcher.py、navigation.py、prompts/patch_navigation.md
- 删除 4 个废弃测试文件：test_cve_agent_llm.py、test_cve_llm_fallback.py、test_page_fetcher.py、test_navigation.py
- 迁移 test_cve_agent_graph.py（FakeBridge + _make_snapshot 模式）
- 精简 test_cve_runtime.py（从 ~1127 行减至 ~235 行）
- 修复 3 个 Review 问题：DRY 导入、排序 O(n²)、LLM 异常日志

### Phase 4：集成测试与调优
- 新增 `test_browser_agent_integration.py`（5 个录制场景集成测试）
- 新增 `fixtures/browser_agent/` 目录（5 场景 × snapshot JSON + LLM response JSON）
- 修复 `agent_state.py` `_browser_bridge` TypedDict 声明（防止 LangGraph 丢失状态）
- 修复 `agent_nodes.py` no_seed_references 提前收口（两处守卫）
- 修复 `detail_service.py` 进度序列证据化判定（避免空 run 误用 7 步序列）

## 本次更新的文档

- `docs/superpowers/specs/2026-04-21-cve-browser-agent-design.md` — 浏览器 Agent 完整设计规格（新增）
- `docs/superpowers/plans/2026-04-21-browser-agent-phase1-prompt.md` — Phase 1 Codex 实施 prompt
- `docs/superpowers/plans/2026-04-21-browser-agent-phase2-prompt.md` — Phase 2 Codex 实施 prompt
- `docs/superpowers/plans/2026-04-21-browser-agent-phase3-prompt.md` — Phase 3 Codex 实施 prompt
- `docs/superpowers/plans/2026-04-21-browser-agent-phase3-cleanup-prompt.md` — Phase 3 清扫 prompt
- `docs/superpowers/plans/2026-04-21-browser-agent-phase4-prompt.md` — Phase 4 Codex 实施 prompt
- `docs/03-系统架构/技术选型.md` — 新增 Playwright/LangGraph 选型与浏览器 Agent 架构定位
- `docs/03-系统架构/架构设计.md` — CVE 场景架构口径切换为浏览器驱动型 Agent
- `docs/04-功能设计/M103-CVE数据源与页面探索规则功能设计.md` — 状态从"设计完成，待实施"更新为"Phase 1-4 实现完成"

## 本次更新的代码

- `backend/app/cve/browser/` — 浏览器层完整包（7 文件）
- `backend/app/cve/browser_agent_llm.py` — LLM 接口
- `backend/app/cve/chain_tracker.py` — 链路追踪器
- `backend/app/cve/canonical.py` — URL 规范化
- `backend/app/cve/frontier_planner.py` — 前沿规划
- `backend/app/cve/prompts/browser_agent_navigation.md` — 导航提示词
- `backend/app/cve/agent_state.py` — 状态定义（重写）
- `backend/app/cve/agent_nodes.py` — 全部节点（重写）
- `backend/app/cve/agent_graph.py` — 图拓扑（重写）
- `backend/app/cve/agent_policy.py` — 策略引擎（重写）
- `backend/app/cve/runtime.py` — 运行时（精简）
- `backend/app/cve/service.py` — 服务层（精简）
- `backend/app/cve/detail_service.py` — 详情服务（修复进度判定）
- `backend/app/config.py` — 配置（新增浏览器配置项）
- `backend/tests/test_browser_agent_integration.py` — 集成测试（新增）
- `backend/tests/test_cve_agent_graph.py` — 图测试（迁移）
- `backend/tests/test_cve_runtime.py` — 运行时测试（精简）
- `backend/tests/test_worker_cve_flow.py` — Worker 流程测试（迁移）

## 关键决策

1. **单路径架构**：废弃 fast-first、httpx Agent、feature flag 分叉和 LLM fallback，只保留 LangGraph + Playwright 一条执行路径。
2. **链路感知停止条件**：用 NavigationChain 状态（in_progress / completed / dead_end）替代简单的"无 frontier 则停"，防止 Agent 在活跃链路存在时早停。
3. **SyncBrowserBridge 桥接**：用独立事件循环线程做 async→sync 转换，避免改造整条 LangGraph 同步管线。
4. **TypedDict 声明 _browser_bridge**：LangGraph 基于 TypedDict annotation 做 channel 管理，不声明会导致 state 穿透时丢字段。
5. **detail_service 证据化判定**：`_is_agent_run` 从只看 job_type 改为同时要求有执行证据（traces/nodes/edges/decisions），避免空 run 误用 7 步进度条。
6. **录制夹具离线测试**：用 JSON snapshot + LLM response 录制做确定性集成测试，不依赖真实网络。
7. **commit 候选折叠**：reference_matcher 识别 commit URL 后直接生成 .patch 候选，无需真实访问 commit 页面。

## 问题与处理

- **DRY 违规**：`_count_consumed_pages` 和 `_unexpanded_frontier_items` 在 agent_policy.py 和 agent_nodes.py 各定义一份 → 保留 agent_policy.py 定义，agent_nodes.py 改为导入
- **LLM 异常吞没**：`except Exception:` 无日志 → 添加 `_logger.warning(..., exc_info=True)`
- **排序 O(n²)**：`order.index()` 在 sort key 中 → 预构建 `order_index` 字典
- **no_seed_references 泄漏**：空种子时图继续执行后续节点导致 stop_reason 被改写 → 两处加 early-return 守卫
- **Phase 4 worktree 未合入 main**：当前 worktree 存在但未 merge；Phase 1-3 变更在 main 上未提交

## 下次计划

1. 合入 Phase 4 worktree 变更到 main（或提交 Phase 1-4 完整变更）
2. 真实网络环境验收（CVE-2022-2509 / CVE-2024-3094 真实运行 + 性能基准采集）
3. 提示词迭代调优（根据真实运行结果分析 LLM 决策质量）
4. 前端搜索图可视化适配（链路状态、页面角色、跨域导航展示）

## 遗留风险

- **性能基准未采集**：设计要求单次运行 ≤ 3 分钟、链路完成率 ≥ 80%，当前仅有离线测试数据（4.26s），真实网络环境下的性能特征未知
- **Phase 1-3 变更未提交**：main 分支有 26 个未提交文件变更，需要整理提交
- **Phase 4 worktree 未合入**：集成测试和生产修复仍在隔离 worktree 中
- **真实 LLM 决策质量未验证**：录制测试使用固定 LLM 响应，真实模型的导航决策质量（尤其是跨域选择和停止判断）需要实际运行观察

## 验收数据

| 测试集 | 结果 |
|--------|------|
| 核心单测（不依赖 DB） | 43 passed, 16 skipped, 4.20s |
| 完整回归（含 DB） | 81 passed, 40.87s |
| Phase 4 集成测试 | 5 passed, 4.26s |
| Phase 3 审查评分 | 95/100 通过 |
| Phase 4 审查评分 | 92/100 通过 |

## 工作模式说明

本轮采用 **设计方案 → Codex 实施 → 审查 → 修复 prompt → Codex 修复 → 再审查** 的协作模式：
- 我（Claude）负责方案设计、审查报告和修复 prompt
- Codex 负责代码实施
- 每个 Phase 交付后进行独立审查，发现问题写修复 prompt 让 Codex 落地
