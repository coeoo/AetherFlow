# Phase 5A 开发提示词：真实网络验收与性能基准

你正在 `/opt/projects/demo/aetherflow` 仓库中实现 CVE Patch 浏览器驱动型 AI Agent 的 Phase 5A。

## 前提

Phase 1-4 已全部完成并合入 main。离线集成测试（录制数据回放）81 passed。
当前缺口：**从未在真实网络环境下运行过**。Phase 5A 的核心任务是在 Docker Compose 环境中用真实 Playwright 浏览器 + PostgreSQL + 真实 LLM 跑完端到端链路，收集性能基准和 LLM 决策质量数据。

## 权威参考

- 设计规格：`docs/superpowers/specs/2026-04-21-cve-browser-agent-design.md`（§10 Phase 4 验收标准中的性能基准要求）
- 模块设计：`docs/04-功能设计/M103-CVE数据源与页面探索规则功能设计.md`
- 运行时入口：`backend/app/cve/runtime.py`（`execute_cve_run` 函数）
- 浏览器后端：`backend/app/cve/browser/playwright_backend.py`（`PlaywrightBackend` + `PlaywrightPool`）
- Docker Compose：`infra/docker-compose.dev.yml`（当前仅有 PostgreSQL）
- 配置项：`backend/app/config.py`（`cve_browser_pool_size`、`cve_browser_headless`、`cve_browser_cdp_endpoint` 等）

## 本轮目标

1. 扩展 Docker Compose 环境，使其支持 Playwright 浏览器（Chromium）+ PostgreSQL
2. 创建真实网络验收测试脚本（不是 pytest 单测，是可独立运行的验收脚本）
3. 用 2 个真实 CVE（CVE-2022-2509、CVE-2024-3094）跑完端到端链路
4. 收集并输出性能基准数据
5. 收集 LLM 决策质量日志用于 Phase 5B 提示词调优

## 交付物

### 1. Docker Compose 扩展 `infra/docker-compose.dev.yml`

在现有 PostgreSQL 服务基础上新增 Playwright 运行支持：

```yaml
services:
  postgres:
    # ...（保持现有配置不变）

  # 新增：安装 Playwright 运行时的验收环境
  acceptance:
    build:
      context: ..
      dockerfile: infra/Dockerfile.acceptance
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      DATABASE_URL: postgresql+psycopg://postgres:postgres@postgres:5432/aetherflow_dev
      # LLM 配置通过 .env 文件或运行时传入
    volumes:
      - ../backend:/app/backend
      - acceptance-results:/app/results
    working_dir: /app

volumes:
  acceptance-results:
```

### 2. Dockerfile `infra/Dockerfile.acceptance`

基于项目的 Python 环境构建，确保包含：

- Python 3.11 + 项目依赖（`pip install -e backend/`）
- Playwright + Chromium（`playwright install --with-deps chromium`）
- 运行时所需的环境变量模板

关键要点：
- 不使用 `cve_browser_cdp_endpoint`（本轮直接在容器内启动 Chromium，不走远程 CDP）
- `cve_browser_headless=true`
- `cve_browser_pool_size=2`（容器资源有限）

### 3. 验收脚本 `backend/scripts/acceptance_browser_agent.py`

独立可运行的 Python 脚本（不是 pytest），核心逻辑：

```
用法: python -m scripts.acceptance_browser_agent [--cve CVE-2022-2509] [--all]
```

#### 3.1 脚本结构

```python
# 主流程：
# 1. 连接 PostgreSQL，初始化 session
# 2. 创建 CVERun 记录
# 3. 调用 execute_cve_run（runtime.py 中的入口）
# 4. 记录运行时长、内存峰值
# 5. 查询搜索图（nodes/edges/decisions）
# 6. 输出结构化报告到 stdout + JSON 文件
```

#### 3.2 验收场景

**场景 A：CVE-2022-2509（GnuTLS Double Free）**

预期链路：NVD advisory → Debian security-tracker → GitLab commit → .patch

验收判定：
- `run.status == "completed"` 或 `run.stop_reason == "patches_downloaded"`
- 至少找到 1 个 patch URL
- 搜索图中存在 `tracker_page` 类型节点（Debian security-tracker）
- 搜索图中存在 `commit_page` 类型节点（GitLab commit）
- 至少 1 条 NavigationChain 状态为 `completed`

**场景 B：CVE-2024-3094（xz-utils 后门）**

预期链路：多域多链路（openwall / Red Hat / GitHub）

验收判定：
- 至少创建 2 条 NavigationChain
- 搜索图中存在跨域边（`edge_type` 含 cross-domain 标识）
- 运行完成（无论是否找到 patch——此 CVE 的 patch 发布方式特殊）

#### 3.3 输出格式

脚本输出结构化 JSON 报告到 `results/acceptance_report.json`：

```json
{
  "timestamp": "2026-04-21T...",
  "scenarios": [
    {
      "cve_id": "CVE-2022-2509",
      "run_id": "...",
      "status": "completed",
      "stop_reason": "patches_downloaded",
      "duration_seconds": 45.2,
      "patch_found": true,
      "patch_urls": ["https://..."],
      "chain_count": 2,
      "completed_chains": 1,
      "dead_end_chains": 1,
      "search_nodes_count": 5,
      "search_edges_count": 4,
      "cross_domain_hops": 2,
      "llm_calls_count": 3,
      "page_roles_visited": ["advisory_page", "tracker_page", "commit_page"],
      "verdict": "PASS"
    }
  ],
  "performance_summary": {
    "total_duration_seconds": 120.5,
    "max_single_run_seconds": 75.3,
    "all_under_3_minutes": true,
    "chain_completion_rate": 0.83
  }
}
```

### 4. LLM 决策质量日志 `results/llm_decisions_log.jsonl`

验收脚本运行时同步输出每次 LLM 调用的详细日志（JSONL 格式）：

```jsonl
{"cve_id": "CVE-2022-2509", "step_index": 1, "page_url": "https://nvd.nist.gov/...", "page_role": "advisory_page", "action": "expand_frontier", "selected_urls": [...], "reason_summary": "...", "cross_domain": false, "latency_ms": 1200}
{"cve_id": "CVE-2022-2509", "step_index": 2, "page_url": "https://security-tracker.debian.org/...", "page_role": "tracker_page", "action": "expand_frontier", "selected_urls": [...], "reason_summary": "...", "cross_domain": true, "latency_ms": 950}
```

实现方式：在 `browser_agent_llm.py` 的 `invoke_browser_agent_llm` 函数中注入日志钩子。**不修改函数签名**，通过 AgentState 中的可选字段 `_llm_decision_log` （`list[dict]`）累积记录，验收脚本运行后从 state 中提取写入文件。

需要在 `agent_state.py` 的 `AgentState` TypedDict 中新增：

```python
_llm_decision_log: list[dict[str, object]]  # 验收用，累积每次 LLM 调用的决策元数据
```

并在 `build_initial_agent_state` 中初始化为空列表。

### 5. 性能基准收集

验收脚本需要收集以下指标：

| 指标 | 验收阈值 | 收集方式 |
|------|---------|---------|
| 单次运行总时长 | ≤180 秒（3 分钟） | `time.perf_counter()` |
| 链路完成率 | ≥80% | `completed_chains / total_chains` |
| LLM 平均响应延迟 | 记录但不设阈值 | 从 `_llm_decision_log` 计算 |
| 页面加载平均耗时 | 记录但不设阈值 | 从 `BrowserPageSnapshot.fetch_duration_ms` 计算 |
| 搜索图节点数 | ≤20（预算上限） | 查询 `cve_search_nodes` |
| 跨域跳转次数 | ≤8（预算上限） | 从 state 读取 `cross_domain_hops` |

### 6. 数据库 Schema 验证

验收脚本运行后，验证以下数据已正确落库：

- `cve_runs` 表：run 记录的 `status`、`stop_reason`、`summary_json` 完整
- `cve_search_nodes` 表：每个已访问页面有对应节点，`page_role` 已填充
- `cve_search_edges` 表：导航关系已记录，跨域边有标识
- `cve_search_decisions` 表：每次 LLM 决策有记录，`input_json` 含 NavigationContext
- `cve_candidate_artifacts` 表：候选 patch 有记录

## 验收标准

1. Docker Compose 环境可一键启动（`docker compose -f infra/docker-compose.dev.yml up`）
2. CVE-2022-2509 验收场景 PASS（找到 patch，链路追踪完整）
3. CVE-2024-3094 验收场景完成运行（多链路创建，跨域边存在）
4. 单次运行 ≤ 3 分钟
5. 链路完成率 ≥ 80%
6. `results/acceptance_report.json` 和 `results/llm_decisions_log.jsonl` 正确输出
7. 数据库落库数据完整（节点、边、决策、候选）

## 约束

- 所有代码注释使用简体中文
- 不修改 DB schema
- 验收脚本独立可运行（不依赖 pytest），方便在 CI 或手动环境中执行
- 不修改现有单元测试或集成测试
- `_llm_decision_log` 是可选字段，离线测试不受影响
- 真实 LLM 调用需要配置 API Key（通过环境变量传入，脚本中不硬编码）
- 如果真实网络环境下某个外部页面不可访问（被墙或下线），在报告中记录为 `SKIP` 并说明原因，不算验收失败
