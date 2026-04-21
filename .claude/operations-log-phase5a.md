# CVE Patch Agent Phase 5A 真实网络验收与调试日志

生成时间：2026-04-21

## 1. 任务概述

Phase 5A 是 CVE Patch 浏览器型 AI Agent 的真实网络验收测试阶段。核心目标：以 CVE-2022-2509（GnuTLS Double Free）和 CVE-2024-3094（xz-utils）为场景，验证 Agent 在真实互联网环境下的端到端 patch 搜索能力。

## 2. 交付物

### 2.1 新增文件

| 文件 | 用途 |
|------|------|
| `docs/superpowers/plans/2026-04-21-browser-agent-phase5a-prompt.md` | Phase 5A Codex 实现提示词 |
| `docs/superpowers/plans/2026-04-21-browser-agent-phase5b-prompt.md` | Phase 5B Codex 实现提示词 |
| `backend/scripts/acceptance_browser_agent.py` | 验收脚本（含场景定义、性能基准、DB 校验、verdict 判定） |
| `backend/tests/test_acceptance_browser_agent.py` | 验收脚本单测 |
| `infra/Dockerfile.acceptance` | 验收容器镜像定义 |
| `infra/docker-compose.dev.yml` | 开发环境扩展（acceptance 服务） |

### 2.2 修改文件（核心业务逻辑）

| 文件 | 改动摘要 |
|------|----------|
| `backend/app/cve/runtime.py` | 新增诊断模式（逐节点执行 + 多轮循环 + 180s 总超时保底） |
| `backend/app/cve/agent_nodes.py` | 节点全面重写：噪声 URL 过滤、高价值链接优先、规则降级决策、下载后全链路关闭 |
| `backend/app/cve/agent_policy.py` | evaluate_stop_condition 新增规则0（patch 已下载即停） |
| `backend/app/cve/browser_agent_llm.py` | NavigationContext 构建 + LLM 调用重试 + 决策/失败日志记录 |
| `backend/app/cve/agent_state.py` | 新增 browser_snapshots、page_role_history 等浏览器状态字段 |
| `backend/app/config.py` | 新增 llm_timeout_seconds、llm_retry_attempts 配置项 |

### 2.3 修改文件（浏览器基础设施）

| 文件 | 改动摘要 |
|------|----------|
| `backend/app/cve/browser/playwright_backend.py` | 空页面/挑战页检测、超时处理优化 |
| `backend/app/cve/browser/sync_bridge.py` | 超时参数化 |
| `backend/app/cve/browser/page_role_classifier.py` | 分类规则扩充 |

### 2.4 修改文件（测试）

| 文件 | 改动摘要 |
|------|----------|
| `backend/tests/test_cve_agent_graph.py` | 大量新增覆盖：链路感知、跨域导航、下载后回流、规则降级 |
| `backend/tests/test_cve_runtime.py` | 诊断模式测试：逐节点提交、多轮循环、单 frontier 强制 |
| `backend/tests/test_browser_agent_llm.py` | LLM 调用重试、决策日志验证 |
| `backend/tests/test_browser_infra.py` | Playwright 基础设施测试 |
| `backend/tests/test_browser_agent_integration.py` | 浏览器 Agent 集成测试 |

## 3. 三轮调试周期

### 3.1 第一轮（P0-P4 分级诊断）

**发现**：
- LLM（DashScope qwen3.6-plus）ReadTimeout → 种子解析阻塞
- 规则降级选择噪声 URL（github/login、nvd/general）
- BrowserContext.close 驱动断连

**修复**：
- LLM 重试机制（`LLM_RETRY_ATTEMPTS=2`）+ 失败日志
- `_GLOBAL_NOISE_PATH_FRAGMENTS` 噪声过滤器
- `_is_high_value_frontier_link` 高价值链接优先

### 3.2 第二轮（深层根因定位）

**发现**：
- 诊断模式只执行一轮，从未循环 → Agent 看不到 security-tracker 页面
- `max_parallel_frontier=3` 导致 `current_page_url` 被最后一个页面覆盖
- `page_roles_visited` 统计了 queued 状态节点（假阳性）
- NVD 页面返回 JS 挑战壳页面

**修复**：
- 重写诊断循环为多轮（最多 5 轮）
- 诊断模式强制 `max_parallel_frontier=1`
- `page_roles_visited` 仅统计 `fetch_status="fetched"` 节点
- 空页面/挑战页检测，跳过无效页面

### 3.3 第三轮（下载后卡死）

**发现**：
- Patch 已成功从 ubuntu.com 下载（DSA-5203 链路完整走通）
- 但 run 停留在 `running/extract_links_and_candidates`，未写最终报告
- 根因：`download_and_validate_node` 只关闭当前链路，其他链路仍 `in_progress` → `evaluate_stop_condition` 规则1 强制继续 → 后续 Playwright/LLM 阻塞

**修复**（三层防线）：
1. `evaluate_stop_condition` 规则0：已有成功下载的 patch → 无条件停止
2. `download_and_validate_node`：下载成功后关闭所有活跃链路
3. 诊断循环增加 180 秒总超时保底

## 4. 测试验证

```
CVE agent 全套测试：35 passed, 43 skipped, 0 failed
全量测试（排除环境依赖）：103+ passed, 0 回归
```

失败项均为既有环境缺失（playwright 未安装、PostgreSQL 未连接），非本次改动引入。

## 5. 架构决策记录

| 决策 | 理由 |
|------|------|
| 诊断模式独立于 LangGraph graph.invoke | 调试可见性：逐节点执行 + 每节点 commit，可精确定位哪个节点失败 |
| 规则0 优先级高于链路活跃检查 | 语义正确性：patch 已找到是终极目标，不应因其他未完成链路而继续 |
| 三层防线而非单点修复 | 鲁棒性：策略层 + 状态层 + 超时层互补，防止边界情况遗漏 |
| `max_parallel_frontier=1`（诊断模式） | 避免多页面覆盖 `current_page_url`，简化调试链路 |

## 6. 已知局限

- 验收需要真实网络环境（Docker + Playwright + PostgreSQL + LLM API），本地无 playwright 无法运行 `test_browser_infra.py`
- NVD 页面 JS 渲染仍无法获取完整内容（已做降级处理，不阻塞主链路）
- Phase 5B（前端可视化、提示词调优、Lightpanda CDP）尚未开始
