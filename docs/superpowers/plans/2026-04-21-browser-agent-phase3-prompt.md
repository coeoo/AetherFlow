# Phase 3 开发提示词：节点重写 + 图改造 + 单路径运行时

你正在 `/opt/projects/demo/aetherflow` 仓库中实现 CVE Patch 浏览器驱动型 AI Agent 的 Phase 3。

## 前提

Phase 1 + Phase 2 已完成，以下模块可直接使用：
- `backend/app/cve/browser/`（完整浏览器基础设施）
- `backend/app/cve/chain_tracker.py`（链路追踪）
- `backend/app/cve/browser_agent_llm.py`（LLM 导航接口 + NavigationContext）
- `backend/app/cve/prompts/browser_agent_navigation.md`（导航提示词）
- `backend/app/cve/agent_state.py`（已含新字段）

## 权威参考

- 设计规格：`docs/superpowers/specs/2026-04-21-cve-browser-agent-design.md`（第 6/7 节）
- 模块设计：`docs/04-功能设计/M103-CVE数据源与页面探索规则功能设计.md`

## 本轮目标

1. 重写 `agent_nodes.py` 所有节点，使用浏览器 + chain-aware LLM
2. 改造 `agent_graph.py`，download_and_validate 增加条件出边
3. 更新 `agent_policy.py`，新预算 + 链路感知停止评估
4. 精简 `runtime.py` 为单路径
5. 删除废弃文件

## 交付物

### 1. `backend/app/cve/agent_policy.py` 重写

更新默认预算：

```python
DEFAULT_PATCH_AGENT_BUDGET = {
    "max_pages_total": 20,
    "max_depth": 6,
    "max_cross_domain_expansions": 8,
    "max_children_per_node": 5,
    "max_parallel_frontier": 3,
    "max_agent_iterations": 15,
    "max_llm_calls": 15,
    "max_llm_tokens": 12000,
    "max_download_attempts": 8,
    "max_chains": 5,
}
```

新增链路感知停止评估：

```python
@dataclass(frozen=True)
class StopEvaluation:
    should_stop: bool
    reason: str

def evaluate_stop_condition(state: dict) -> StopEvaluation:
    """
    规则1：有活跃链路且预算未耗尽 → 不停
    规则2：有候选且所有链路已终止 → 停
    规则3：无活跃链路 + 无 frontier + 无候选 → 停
    """
```

收紧 `needs_human_review` 接受条件：

```python
def validate_needs_human_review(state: dict) -> bool:
    """
    仅当同时满足以下条件时接受 needs_human_review：
    1. 没有活跃链路（in_progress）
    2. 没有未扩展的 frontier
    3. 没有从链路上下文推导出的跨域候选链接
    否则强制覆盖为继续探索。
    """
```

保留现有 `validate_agent_decision` 函数，但更新 `allowed_urls` 逻辑以兼容 BrowserPageSnapshot 的 links 字段。

### 2. `backend/app/cve/agent_nodes.py` 全量重写

每个节点的改造要点：

#### `resolve_seeds_node`（不变）
- 继续使用现有 seed_resolver，无需浏览器
- 只确保输出格式与新 state 字段兼容

#### `build_initial_frontier_node`（小改）
- 对 seed URL 调用 `page_role_classifier.classify_page_role()` 分类角色
- 基于页面角色初始化 NavigationChain（通过 ChainTracker）
- 将 chain 信息写入 state["navigation_chains"]

#### `fetch_next_batch_node`（重写）
- 从 `state["selected_frontier_urls"]` 取 URL
- 使用 `SyncBrowserBridge.navigate()` 替代 `page_fetcher.fetch_page()`
- 将 BrowserPageSnapshot 序列化存入 `state["browser_snapshots"]`
- 更新 `state["page_observations"]` 以保持与搜索图服务兼容
- 更新 `state["visited_urls"]`

#### `extract_links_and_candidates_node`（重写）
- 从 `state["browser_snapshots"]` 取最新快照
- 结构化链接直接来自 `BrowserPageSnapshot.links`（不再需要从 HTML 解析）
- 继续使用 `page_analyzer.analyze_page()` 从 raw_html 提取候选
- 继续使用 `reference_matcher.match_reference_url()` 匹配已知模式
- 更新 `state["frontier"]` 和 `state["direct_candidates"]`

#### `agent_decide_node`（重写）
- 使用 `browser_agent_llm.build_llm_page_view()` + `build_navigation_context()` 构建上下文
- 调用 `browser_agent_llm.call_browser_agent_navigation()` 获取决策
- 处理 LLM 返回的 `chain_updates`：调用 ChainTracker 更新链路
- 处理 `new_chains`：创建新链路
- 调用 `validate_agent_decision()` 校验决策
- 在 `needs_human_review` 时，调用 `validate_needs_human_review()` 判断是否强制继续
- 调用 `evaluate_stop_condition()` 判断全局停止
- 写入 `state["decision_history"]`

#### `download_and_validate_node`（小改）
- 保留现有下载和校验逻辑
- **关键改变**：返回后不固定走 finalize_run，而是检查 evaluate_stop_condition
- 如果 should_stop=False，设置 state["next_action"] = "fetch_next_batch"
- 下载成功时，调用 ChainTracker.complete_chain()

#### `finalize_run_node`（小改）
- summary_json 中包含链路摘要（从 ChainTracker.to_dict_list() 获取）
- 包含页面角色统计
- 包含跨域跳转次数

### 3. `backend/app/cve/agent_graph.py` 改造

修改 `download_and_validate` 后的路由：

```python
# 当前：download_and_validate → finalize_run（固定）
# 改为：download_and_validate → 条件路由
graph.add_conditional_edges(
    "download_and_validate",
    _route_after_download,
    {
        "fetch_next_batch": "fetch_next_batch",
        "finalize_run": "finalize_run",
    },
)

def _route_after_download(state: AgentState) -> str:
    if state.get("next_action") == "fetch_next_batch":
        return "fetch_next_batch"
    return "finalize_run"
```

### 4. `backend/app/cve/runtime.py` 精简

删除所有路径分叉逻辑，只保留一条路径：

```python
def execute_cve_run(session, *, run, run_id: str, cve_id: str) -> None:
    """唯一执行路径：浏览器驱动型 Patch Agent"""
    bridge = SyncBrowserBridge(PlaywrightBackend(...))
    bridge.start()
    try:
        state = build_initial_agent_state(run_id=run_id, cve_id=cve_id)
        state["session"] = session
        graph = build_cve_patch_graph()
        # 将 bridge 注入到 state 或通过闭包传给节点
        final_state = graph.invoke(state)
        ...
    finally:
        bridge.stop()
```

删除以下引用/逻辑：
- fast-first 路径
- httpx agent graph 路径
- feature flag 检查（`cve_agent_graph_enabled` 等）
- LLM fallback 逻辑

### 5. `backend/app/config.py` 清理

删除旧配置项（如存在）：
- `cve_agent_graph_enabled`
- `cve_llm_fallback_enabled`
- `cve_browser_enabled`

确认 Phase 1 新增的浏览器配置项存在。

### 6. 删除废弃文件

- `backend/app/cve/page_fetcher.py`
- `backend/app/cve/agent_llm.py`
- `backend/app/cve/llm_fallback.py`（如果存在）
- `backend/app/cve/navigation.py`（如果存在）
- `backend/app/cve/prompts/patch_navigation.md`

删除前确认没有其他模块引用这些文件。如有引用，一并更新。

## 验收标准

更新 `backend/tests/test_cve_agent_graph.py`：

1. **完整图运行**（fake browser + fake LLM）：Agent 走完 advisory→tracker→commit 链路
   - 构造 fake BrowserPageSnapshot 序列（NVD 页面 → Debian tracker → GitLab commit）
   - 构造 fake LLM 响应序列（expand_frontier → expand_frontier → try_candidate_download → stop_search）
   - 验证最终 state 包含正确的 patches 和链路摘要

2. **活跃链路不早停**：有 in_progress 链路时，即使 LLM 返回 stop_search，evaluate_stop_condition 强制继续

3. **跨域导航扣减预算**：每次跨域 expand_frontier 后 max_cross_domain_expansions 递减

4. **download 后回到 fetch**：download_and_validate 成功但仍有活跃链路时，路由回 fetch_next_batch

5. **needs_human_review 收紧**：有活跃链路时 needs_human_review 被强制覆盖

更新 `backend/tests/test_cve_runtime.py`：
1. runtime.py 只有一条路径，不再有路径分叉测试

更新 `backend/tests/test_cve_api.py`：
1. 确保 API 测试与新 runtime 兼容

## 约束

- 所有代码注释使用简体中文
- 浏览器 bridge 注入方式：推荐通过 state 传入（`state["_browser_bridge"]`），避免全局变量
- 保持与现有 `search_graph_service.py` 的写入接口兼容（节点、边、决策、候选）
- 删除文件前用 grep 确认无其他引用
- 旧测试中与 fast-first 或 httpx agent 相关的用例直接删除
