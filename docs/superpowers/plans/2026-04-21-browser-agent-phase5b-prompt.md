# Phase 5B 开发提示词：前端链路可视化、提示词调优与 Lightpanda CDP 验证

你正在 `/opt/projects/demo/aetherflow` 仓库中实现 CVE Patch 浏览器驱动型 AI Agent 的 Phase 5B。

## 前提

Phase 1-4 已全部完成并合入 main（离线集成测试 81 passed）。Phase 5A 已完成真实网络验收，产出了：
- `results/acceptance_report.json`（性能基准）
- `results/llm_decisions_log.jsonl`（LLM 决策质量日志）

Phase 5B 的任务是三个并行方向：
1. **前端详情页适配**：展示浏览器 Agent 产出的链路追踪、页面角色、跨域导航等新数据
2. **提示词调优**：基于 Phase 5A 的 LLM 决策日志分析问题并改进提示词
3. **Lightpanda CDP 验证**：验证通过 CDP 端点连接 Lightpanda 的可行性

## 权威参考

- 设计规格：`docs/superpowers/specs/2026-04-21-cve-browser-agent-design.md`
- 模块设计：`docs/04-功能设计/M103-CVE数据源与页面探索规则功能设计.md`（§界面设计）
- 前端详情页：`frontend/src/routes/CVERunDetailPage.tsx`
- 前端类型定义：`frontend/src/features/cve/types.ts`
- 前端 API 层：`frontend/src/features/cve/api.ts`
- 后端详情接口：`backend/app/cve/detail_service.py`（`get_cve_run_detail` 函数）
- 链路追踪：`backend/app/cve/chain_tracker.py`（`NavigationChain` / `ChainStep`）
- 导航提示词：`backend/app/cve/prompts/browser_agent_navigation.md`
- 浏览器后端：`backend/app/cve/browser/playwright_backend.py`（CDP 连接路径）
- 配置项：`backend/app/config.py`（`cve_browser_cdp_endpoint`）

## 交付物 1：前端详情页链路可视化

### 1.1 后端接口扩展

当前 `get_cve_run_detail`（`detail_service.py:58`）已返回 `search_graph`（含 `nodes` + `edges`）和 `decision_history`，但前端 `CVERunDetail` 类型定义（`types.ts:109`）尚未包含这些字段，前端也未渲染。

需要完成以下对齐：

#### 1.1.1 后端：在 `summary_json` 中追加 `chain_summary`

在 `agent_nodes.py` 的 `finalize_run_node` 中，确保 `summary_json` 包含链路摘要：

```python
# summary_json 应包含：
{
    "runtime_kind": "patch_agent_graph",
    "patch_found": True/False,
    "patch_count": N,
    "chain_summary": [
        {
            "chain_id": "chain-xxx",
            "chain_type": "advisory_to_patch",
            "status": "completed",
            "steps": [
                {"url": "https://nvd.nist.gov/...", "page_role": "advisory_page", "depth": 0},
                {"url": "https://security-tracker.debian.org/...", "page_role": "tracker_page", "depth": 1},
                {"url": "https://gitlab.com/.../commit/...", "page_role": "commit_page", "depth": 2}
            ]
        }
    ],
    "cross_domain_hops": 2,
    "pages_visited": 5,
    "budget_usage": {
        "pages": {"used": 5, "max": 20},
        "llm_calls": {"used": 3, "max": 15},
        "cross_domain": {"used": 2, "max": 8}
    }
}
```

检查 `finalize_run_node` 当前实现是否已包含上述字段。如果缺失，补充。数据来源：
- `chain_summary`：从 `state["navigation_chains"]` 读取
- `cross_domain_hops`：从 `state["cross_domain_hops"]` 读取
- `budget_usage`：从 `state["pages_visited"]`、`state["llm_calls_count"]` 等预算字段计算

#### 1.1.2 后端：确保 `detail_service.py` 透传 `chain_summary`

当前 `get_cve_run_detail` 返回的 `summary` 字段直接是 `run.summary_json`，无需额外处理——只要 `finalize_run_node` 写入正确即可。

但需要确认 `search_graph`、`decision_history` 字段已在返回值中（当前已有，确认即可）。

### 1.2 前端类型扩展

在 `frontend/src/features/cve/types.ts` 中扩展：

```typescript
// 新增类型
export type CVEChainStep = {
  url: string;
  page_role: string;
  depth: number;
};

export type CVEChainSummary = {
  chain_id: string;
  chain_type: string;
  status: string;  // "completed" | "dead_end" | "in_progress"
  steps: CVEChainStep[];
};

export type CVEBudgetUsage = {
  used: number;
  max: number;
};

export type CVESearchNode = {
  node_id: string;
  url: string;
  depth: number;
  host: string;
  page_role: string | null;
  fetch_status: string;
};

export type CVESearchEdge = {
  from_node_id: string;
  to_node_id: string;
  edge_type: string;
  selected_by: string;
};

export type CVESearchDecision = {
  decision_id: string;
  step_index: number;
  action: string;
  validated: boolean;
  reason_summary: string | null;
  input_json: Record<string, unknown>;
  output_json: Record<string, unknown>;
  created_at: string;
};

// 扩展现有 CVERunSummary
export type CVERunSummary = {
  // ...保持现有字段...
  chain_summary?: CVEChainSummary[];
  cross_domain_hops?: number;
  pages_visited?: number;
  budget_usage?: {
    pages?: CVEBudgetUsage;
    llm_calls?: CVEBudgetUsage;
    cross_domain?: CVEBudgetUsage;
  };
};

// 扩展现有 CVERunDetail
export type CVERunDetail = {
  // ...保持现有字段...
  search_graph?: {
    nodes: CVESearchNode[];
    edges: CVESearchEdge[];
  };
  decision_history?: CVESearchDecision[];
};
```

### 1.3 前端组件：链路追踪面板

新增 `frontend/src/features/cve/components/CVEChainTracker.tsx`：

**功能**：展示每条 NavigationChain 的状态和步骤

**设计要求**：
- 每条链路显示为一个卡片：标题（chain_type 中文标签）、状态徽标（completed=绿色、dead_end=红色、in_progress=蓝色）
- 链路步骤展示为水平时间线：每个节点显示 page_role 图标/标签 + 域名缩写
- 跨域步骤用虚线连接（同域用实线）
- 步骤可点击，展开显示完整 URL

**chain_type 中文映射**：
- `advisory_to_patch` → "公告→补丁"
- `tracker_to_commit` → "追踪器→提交"
- `mailing_list_to_fix` → "邮件列表→修复"

**page_role 中文映射**：
- `advisory_page` → "安全公告"
- `tracker_page` → "安全追踪器"
- `commit_page` → "代码提交"
- `download_page` → "下载页"
- `mailing_list_page` → "邮件列表"
- `bugtracker_page` → "Bug 追踪器"
- `pull_request_page` → "Pull Request"
- `repository_page` → "代码仓库"

### 1.4 前端组件：预算消耗面板

新增 `frontend/src/features/cve/components/CVEBudgetPanel.tsx`：

**功能**：展示搜索预算的消耗情况

**设计要求**：
- 三个进度条：页面预算（pages）、LLM 调用（llm_calls）、跨域跳转（cross_domain）
- 每个进度条显示 `已用/上限`
- 颜色：<50% 绿色、50-80% 黄色、>80% 红色
- 仅在 `summary.budget_usage` 存在时渲染

### 1.5 前端组件：搜索图节点页面角色着色

修改现有搜索图渲染（如果已有）或在 `CVERunDetailPage.tsx` 中新增搜索图区域：

**设计要求**：
- 搜索图节点按 `page_role` 着色：
  - `advisory_page`: 蓝色
  - `tracker_page`: 紫色
  - `commit_page`: 绿色
  - `download_page`: 金色
  - 其他: 灰色
- 跨域边用虚线，同域边用实线
- 节点 hover 显示完整 URL + page_role 中文标签
- 如果没有现成的图渲染库，使用简洁的列表+缩进树形式代替力导向图（不引入重量级可视化依赖）

### 1.6 详情页布局集成

修改 `CVERunDetailPage.tsx`，在现有布局中集成新组件：

```
<CVEVerdictHero />

<section 当前运行状态>...</section>

{/* 新增：仅在 Agent run 时显示 */}
{detail.summary?.chain_summary && (
  <>
    <CVEChainTracker chains={detail.summary.chain_summary} />
    <CVEBudgetPanel budget={detail.summary.budget_usage} />
  </>
)}

<section cve-detail-grid>
  <CVEDiffViewer />
  <aside>
    <CVEFixFamilySummary />
    <CVEPatchList />
    <CVETraceTimeline />
  </aside>
</section>
```

判定是否是 Agent run 的依据：`detail.summary?.chain_summary` 存在且非空。

### 1.7 CSS 样式

使用项目既有的 CSS 变量和类名约定。参考 `CVETraceTimeline`、`CVEPatchList` 等现有组件的样式模式。不引入新的 CSS 框架或 CSS-in-JS 方案。

## 交付物 2：提示词调优

### 2.1 分析 LLM 决策日志

读取 Phase 5A 产出的 `results/llm_decisions_log.jsonl`，分析以下问题模式：

| 问题模式 | 检测方式 | 对应提示词改进 |
|---------|---------|--------------|
| LLM 在 tracker 页面不选择跨域 commit 链接 | `page_role == "tracker_page"` 但 `action != "expand_frontier"` 或未选跨域 URL | 强化"典型链路模式"部分 |
| LLM 过早停止 | `action == "stop_search"` 但仍有 `in_progress` 链路 | 强化"所有活跃链路终止前不得 stop_search" |
| LLM 选择无关链接 | 选择的 URL 不在 `key_links` 中，或 `estimated_target_role` 与链路预期不符 | 强化"只能从 key_links 列表中选择" |
| LLM 重复访问已访问域 | `selected_urls` 的域名在 `visited_domains` 中 | 强化"避免重复访问已探索域" |

### 2.2 调优 `backend/app/cve/prompts/browser_agent_navigation.md`

基于 2.1 的分析结果，修改提示词。每次修改需要：

1. 在提示词文件的对应章节做出修改
2. 在提示词文件末尾添加变更日志：

```markdown
## 变更日志

### 2026-04-21 Phase 5B 调优
- [问题]：LLM 在 tracker 页面倾向于选择同域链接
- [改进]：在"典型链路模式"部分新增明确的跨域导航示例
- [依据]：Phase 5A 决策日志分析，CVE-2022-2509 场景第 2 步
```

### 2.3 调优验证

修改提示词后，运行现有离线集成测试确保不回归：

```bash
TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev \
timeout 120s ./.venv/bin/python -m pytest \
  backend/tests/test_browser_agent_integration.py \
  backend/tests/test_browser_agent_llm.py \
  -q
```

注意：离线测试使用录制的 LLM 响应，提示词变更不会影响录制数据的回放结果。这里只是确保提示词文件本身格式正确、加载无误。

## 交付物 3：Lightpanda CDP 验证

### 3.1 验证脚本 `backend/scripts/verify_lightpanda_cdp.py`

独立可运行的 Python 脚本，验证通过 CDP 端点连接 Lightpanda 的可行性：

```python
# 用法: python -m scripts.verify_lightpanda_cdp --endpoint ws://localhost:9222
#
# 验证步骤：
# 1. 通过 Playwright connect_over_cdp 连接指定端点
# 2. 打开一个简单页面（https://httpbin.org/html）
# 3. 获取 page.accessibility.snapshot()
# 4. 获取 page.content()
# 5. 执行链接提取 JS（_LINK_EXTRACTION_SCRIPT）
# 6. 报告每一步的成功/失败和耗时
```

### 3.2 配置验证

确认以下配置组合在代码中可正常工作：

```python
# config.py 中的配置
cve_browser_cdp_endpoint: str = "ws://localhost:9222"  # 非空时走 CDP 路径
```

检查 `PlaywrightPool.__init__` 和 `PlaywrightPool.start` 中的 CDP 分支路径：

```python
# playwright_backend.py 中已有的逻辑：
if self._cdp_endpoint:
    self._browser = await chromium.connect_over_cdp(self._cdp_endpoint)
else:
    self._browser = await chromium.launch(headless=self._headless)
```

验证此路径在以下场景下正确工作：
- CDP 端点可达：正常连接
- CDP 端点不可达：抛出明确错误（不挂起）
- CDP 连接中断后重连：当前实现是否有重连机制（如果没有，记录为已知限制即可，不要求实现）

### 3.3 文档更新

在 `docs/04-功能设计/M103-CVE数据源与页面探索规则功能设计.md` 的"核心架构 → 浏览器层"部分，补充 Lightpanda CDP 验证结果：

```markdown
### Lightpanda CDP 验证状态

| 能力 | 状态 | 备注 |
|------|------|------|
| CDP 连接 | ✅ 已验证 / ❌ 未验证 | |
| a11y snapshot | ✅ / ❌ | Lightpanda 是否支持 |
| DOM content | ✅ / ❌ | |
| JS 执行（链接提取） | ✅ / ❌ | |
```

如果没有可用的 Lightpanda 实例进行实际验证，将所有状态标记为"待验证"并保留脚本即可。

## 交付物 4：全量回归

确保以下测试全部通过：

```bash
TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev \
timeout 120s ./.venv/bin/python -m pytest \
  backend/tests/test_browser_infra.py \
  backend/tests/test_chain_tracker.py \
  backend/tests/test_browser_agent_llm.py \
  backend/tests/test_cve_agent_graph.py \
  backend/tests/test_browser_agent_integration.py \
  backend/tests/test_search_graph_service.py \
  backend/tests/test_cve_detail_service.py \
  backend/tests/test_cve_api.py \
  backend/tests/test_cve_runtime.py \
  -q
```

前端构建无报错：

```bash
cd frontend && npm run build
```

## 验收标准

### 前端
1. 详情页在 Agent run 时展示链路追踪面板（CVEChainTracker）
2. 详情页在 Agent run 时展示预算消耗面板（CVEBudgetPanel）
3. 搜索图节点按 page_role 着色
4. 跨域边用虚线区分
5. 非 Agent run（旧数据）的详情页不受影响
6. `npm run build` 无报错

### 提示词调优
7. `browser_agent_navigation.md` 包含基于决策日志的改进
8. 变更日志记录改进依据
9. 离线测试通过

### Lightpanda
10. CDP 验证脚本可运行
11. M103 文档更新 CDP 验证状态

### 回归
12. 全量后端测试通过
13. 无 import 错误

## 约束

- 所有代码注释使用简体中文
- 不修改 DB schema
- 前端不引入新的 CSS 框架或重量级可视化库
- 前端组件遵循项目既有的组件模式（参考 `CVETraceTimeline`、`CVEPatchList`）
- 提示词调优基于数据驱动（Phase 5A 日志），不做主观臆断式修改
- Lightpanda 验证是可行性验证，不要求生产级实现
- 如果 `results/llm_decisions_log.jsonl` 不存在（Phase 5A 未执行），提示词调优部分跳过，仅做格式和加载验证
