# Phase 3 收口：Review 修复 + 废弃文件/测试清扫

## 背景

Phase 3 核心主链切换已完成（浏览器 Agent 单路径运行时、链路感知策略、图条件路由）。本次任务目标：

1. 修复 Phase 3 Review 标记的 2 个 Medium + 1 个 Low 问题
2. 删除已废弃的生产代码文件
3. 清扫或迁移引用旧模块的测试
4. 确保 `pytest backend/tests/ -q --ignore=backend/tests/test_worker_cve_flow.py --ignore=backend/tests/test_cve_api.py -k 'not test_post_run_then_worker'` 全部通过（不依赖 TEST_DATABASE_URL 的测试子集）

**关键约束**：
- `page_analyzer.py` 仍在使用（`agent_nodes.py:23,806`），**不要删除**
- `detail_service.py` 保留了 `_LEGACY_PHASES`（兼容旧 DB 记录），**不要修改**
- `worker/runtime.py:67` 保留 `cve_patch_fast_first` 兼容（迁移安全），**不要修改**
- 所有改动仅限 `backend/` 目录
- 只给出 unified diff patch，**不要对代码做任何真实修改**

---

## 第一部分：Review 修复（3 项）

### 1.1 DRY 违规修复（Medium）

`_count_consumed_pages` 和 `_unexpanded_frontier_items` 在 `agent_policy.py` 和 `agent_nodes.py` 中各定义了一份，逻辑完全相同。

**修复方案**：
- 保留 `agent_policy.py` 中的定义（它们本质是策略计算函数）
- 在 `agent_nodes.py` 中删除重复定义，改为从 `agent_policy` 导入：

```python
# agent_nodes.py 新增导入
from app.cve.agent_policy import _count_consumed_pages  # noqa: 仅内部复用
from app.cve.agent_policy import _unexpanded_frontier_items  # noqa: 仅内部复用
```

注意：`agent_policy.py` 中这两个函数的签名用的是 `state` 参数（普通 dict），而 `agent_nodes.py` 中用的是 `state: AgentState`。由于 `AgentState` 是 `TypedDict` 且两处实际访问方式一致（`.get()`），类型兼容没有问题。

### 1.2 LLM 异常日志（Medium）

`agent_nodes.py:973` 的 `except Exception:` 吞掉了 `call_browser_agent_navigation` 的全部异常。

**修复方案**：在 `agent_nodes.py` 文件顶部添加 `import logging`，创建 `_logger = logging.getLogger(__name__)`，然后在 `except Exception:` 块中添加一行日志：

```python
except Exception:
    _logger.warning("LLM 导航决策调用失败，回退到规则引擎", exc_info=True)
    validation = None
    action = "stop_search"
    selected_urls = []
```

### 1.3 排序复杂度修复（Low）

`agent_nodes.py` 的 `_build_primary_family_summary` 函数（约第 339-346 行）在排序 key 中使用 `order.index(...)`，每次比较都是 O(n)。

**修复方案**：在排序前构建索引字典：

```python
order_index = {key: idx for idx, key in enumerate(order)}
primary_family = sorted(
    (grouped[key] for key in order),
    key=lambda family: (
        -int(family["downloaded_patch_count"]),
        -int(family["patch_count"]),
        order_index.get(f"family:{family['source_url']}", len(order)),
    ),
)[0]
```

---

## 第二部分：删除废弃生产代码（5 个文件）

以下文件的功能已被浏览器 Agent 模块替代，生产代码中已无任何导入：

| 待删除文件 | 替代方 |
|-----------|--------|
| `backend/app/cve/agent_llm.py` | `backend/app/cve/browser_agent_llm.py` |
| `backend/app/cve/llm_fallback.py` | 不再需要（浏览器 Agent 图内建了规则回退） |
| `backend/app/cve/page_fetcher.py` | `backend/app/cve/browser/playwright_backend.py` |
| `backend/app/cve/navigation.py` | 链接排序逻辑已合并到 `browser/` 和 `frontier_planner.py` |
| `backend/app/cve/prompts/patch_navigation.md` | `backend/app/cve/prompts/browser_agent_navigation.md` |

**注意**：`page_analyzer.py` 仍在使用，**绝对不要删除**。

---

## 第三部分：删除废弃测试文件（2 个文件）

| 待删除测试 | 原因 |
|-----------|------|
| `backend/tests/test_cve_agent_llm.py` | 测试旧 `agent_llm.py`，已被 `test_browser_agent_llm.py` 替代 |
| `backend/tests/test_cve_llm_fallback.py` | 测试旧 `llm_fallback.py`，浏览器 Agent 不再有独立 LLM fallback 模块 |
| `backend/tests/test_page_fetcher.py` | 测试旧 `page_fetcher.py`，已被 `test_browser_infra.py` 替代 |

---

## 第四部分：迁移遗留测试引用

### 4.1 test_cve_agent_graph.py — 迁移 6 个遗留测试

**需要改写的测试**（它们 mock 了不再存在的函数）：

#### 4.1.1 `test_patch_agent_graph_records_seed_candidates_frontier_and_decision`（约第 42-116 行）

当前问题：mock `app.cve.agent_nodes.fetch_page` 和 `app.cve.agent_nodes.analyze_page`，但新 agent_nodes 不再导入 `fetch_page`。

**改写策略**：这是个端到端图运行测试，需要 mock browser bridge。改写为：

1. 创建 `_FakeBridge` 类，`navigate()` 返回固定 `BrowserPageSnapshot`
2. 将 bridge 注入 state：`state["_browser_bridge"] = _FakeBridge()`
3. mock `app.cve.agent_nodes.call_browser_agent_navigation` 返回 `try_candidate_download`
4. mock `app.cve.agent_nodes.download_patch_candidate` 保持不变
5. 验证断言保持不变（seed_references、frontier、direct_candidates、decision_history）

`_FakeBridge` 模板：

```python
from app.cve.browser.base import BrowserPageSnapshot, PageLink

class _FakeBridge:
    def navigate(self, url: str, *, timeout_ms: int = 30000) -> BrowserPageSnapshot:
        return BrowserPageSnapshot(
            url=url,
            final_url=url,
            status_code=200,
            title="fake",
            raw_html="<html><body>no extra links</body></html>",
            accessibility_tree="",
            markdown_content="",
            links=[],
            page_role_hint="unknown_page",
            fetch_duration_ms=100,
        )

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass
```

#### 4.1.2 `test_fetch_next_batch_node_honors_selected_frontier_urls`（约第 274-319 行）

当前问题：mock `app.cve.agent_nodes.fetch_page`。

**改写策略**：注入 `_FakeBridge` 到 state，删除 `fetch_page` monkeypatch。`_FakeBridge.navigate()` 根据 URL 返回对应的快照。验证断言不变。

#### 4.1.3 `test_fetch_next_batch_node_materializes_frontier_before_agent_decide`（约第 245-272 行）

与 4.1.2 相同策略：注入 `_FakeBridge`，删除旧的 `fetch_page` mock。这个测试当前不 mock `fetch_page`——它直接调用 `fetch_next_batch_node`。但新的 `fetch_next_batch_node` 需要 `state["_browser_bridge"]` 存在，否则会 raise `ValueError`。所以需要加上 `state["_browser_bridge"] = _FakeBridge()`。

#### 4.1.4 `test_agent_decide_node_uses_fake_llm_expand_frontier`（约第 444-516 行）

当前问题：mock `app.cve.agent_nodes.call_agent_navigation`，但新代码用 `call_browser_agent_navigation`。

**改写策略**：
1. 将 monkeypatch target 改为 `app.cve.agent_nodes.call_browser_agent_navigation`
2. 在 state 中添加 `browser_snapshots` 条目（包含至少一个 link），使 `build_llm_page_view` 能构建 page view
3. Lambda 签名从 `lambda state, page_observation: {...}` 改为 `lambda navigation_context: {...}`（新函数签名只接受 `NavigationContext`）
4. 返回值增加 `chain_updates: []` 和 `new_chains: []` 字段

注意：由于 `agent_decide_node` 内部先调用 `build_llm_page_view` 和 `build_navigation_context`（需要 `browser_snapshots` 存在），必须确保 state 中有对应的快照数据。

#### 4.1.5 `test_agent_decide_node_records_rejected_llm_url_and_falls_back`（约第 518-561 行）

同 4.1.4 策略：
1. monkeypatch target 改为 `call_browser_agent_navigation`
2. 添加 `browser_snapshots`
3. 调整 lambda 签名

#### 4.1.6 `test_agent_decide_node_invalid_duplicate_llm_result_uses_filtered_fallback`（约第 603-653 行）

同 4.1.4 策略。

#### 4.1.7 `test_agent_decide_node_overrides_needs_human_review_when_expandable_frontier_exists`（约第 656-701 行）

同 4.1.4 策略。

#### 4.1.8 `test_extract_links_and_candidates_node_appends_frontier_edge_and_candidate`（约第 704-772 行）

当前问题：mock `collect_follow_links`（已不存在）和 `analyze_page`。

**改写策略**：
1. 删除 `collect_follow_links` monkeypatch
2. 在 `state["browser_snapshots"]` 中为 `"https://example.com/root"` 放入包含 links 的快照（使 `extract_links_and_candidates_node` 直接从快照提取链接）
3. `analyze_page` mock 可以保留（`agent_nodes.py` 仍然导入并使用 `analyze_page`）
4. 确保 `page_observations["https://example.com/root"]["extracted"]` 为 `False`（触发提取逻辑）

#### 4.1.9 `test_agent_decide_node_fallback_limits_cross_domain_expansion`（约第 564-600 行）

当前问题：mock `call_agent_navigation`（抛出 TimeoutError）。

**改写策略**：
1. monkeypatch target 改为 `call_browser_agent_navigation`
2. 由于这个测试故意让 LLM 超时以触发规则回退，不需要 `browser_snapshots`（`raw_snapshot` 为空时直接走规则回退分支）
3. 断言不变

### 4.2 test_cve_runtime.py — 删除 + 迁移

新的 `runtime.py` 只有 ~72 行，职责仅是：创建 bridge → 构建图 → 注入 state → invoke → 异常兜底。大部分旧测试测的是旧 runtime 内联的业务逻辑（fetch_page → analyze_page → download），这些逻辑现在在 `agent_nodes.py` 里。

**删除以下测试**（它们测试的场景已被其他测试覆盖或不再适用）：

| 测试名 | 删除原因 |
|--------|---------|
| `test_execute_cve_run_downloads_patch_and_updates_summary` | 测旧内联逻辑，已被 agent_graph 测试覆盖 |
| `test_execute_cve_run_persists_discovery_metadata_into_patch_meta_json` | 同上 |
| `test_execute_cve_run_accumulates_multiple_discovery_sources_for_same_candidate` | 同上 |
| `test_execute_cve_run_marks_patch_download_failure` | 同上 |
| `test_execute_cve_run_marks_failure_when_page_analysis_raises` | 旧 phase `analyze_page` 不再存在 |
| `test_execute_cve_run_dispatches_to_agent_graph_when_feature_flag_enabled` | 不再有 feature flag 分叉 |
| `test_execute_cve_run_consumes_direct_seed_candidates_beyond_page_budget` | 测旧内联逻辑 |
| `test_execute_cve_run_tolerates_failed_page_fetch_when_other_pages_produce_patch_candidates` | 测旧内联逻辑 |
| `test_execute_cve_run_writes_source_fetch_records_without_breaking_summary` | 需要 httpx mock + DB，属于集成测试范畴 |
| `test_execute_cve_run_deduplicates_patch_candidates_across_pages` | 测旧内联逻辑 |
| `test_execute_cve_run_does_not_trigger_llm_fallback_when_disabled` | LLM fallback 不再是独立模块 |
| `test_execute_cve_run_triggers_llm_fallback_for_no_patch_candidates` | 同上 |
| `test_execute_cve_run_persists_skipped_llm_fallback_audit_when_provider_config_missing` | 同上 |
| `test_execute_cve_run_triggers_llm_fallback_for_patch_download_failed` | 同上 |

**保留并确保通过**：

| 测试名 | 说明 |
|--------|------|
| `test_execute_cve_run_fails_with_no_seed_references` | 需改写：mock browser bridge + graph |
| `test_execute_cve_run_marks_failure_when_seed_resolution_raises` | 需改写：同上 |
| `test_execute_cve_run_uses_browser_agent_single_path` | 已适配新架构，保持不变 |
| `test_plan_frontier_*`（5 个） | 测 `frontier_planner.py`（未改动），保持不变 |

**改写 `test_execute_cve_run_fails_with_no_seed_references`**：

当前 mock `app.cve.runtime.resolve_seed_references`，但新 runtime 不直接导入它。改为：

```python
def test_execute_cve_run_fails_with_no_seed_references(db_session, monkeypatch) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    db_session.commit()

    monkeypatch.setattr(
        "app.cve.agent_nodes.resolve_seed_references",
        lambda session, *, run, cve_id: [],
    )

    class _FakeBridge:
        def start(self): pass
        def stop(self): pass

    monkeypatch.setattr("app.cve.runtime.SyncBrowserBridge", lambda backend: _FakeBridge())
    monkeypatch.setattr("app.cve.runtime.PlaywrightBackend", lambda **kwargs: object())

    execute_cve_run(db_session, run_id=run.run_id)
    db_session.commit()

    reloaded = db_session.get(CVERun, run.run_id)
    assert reloaded.status == "failed"
    assert reloaded.stop_reason == "no_seed_references"
```

**改写 `test_execute_cve_run_marks_failure_when_seed_resolution_raises`**：

同理 mock `app.cve.agent_nodes.resolve_seed_references` 抛异常，加上 fake bridge。

### 4.3 test_worker_cve_flow.py — 迁移 3 个测试

#### 4.3.1 `test_post_run_then_worker_once_then_get_summary_returns_terminal_state`

当前问题：mock `page_fetcher.http_client.get`、`runtime.analyze_page`、`runtime.plan_frontier`。

**改写策略**：这是端到端 worker → runtime → graph 流程。新 runtime 只调用 graph.invoke()。最简单的方式是 mock 整个图执行：

```python
def _fake_graph_invoke(state):
    # 模拟一次成功运行
    session = state["session"]
    run = session.get(CVERun, UUID(state["run_id"]))
    run.status = "succeeded"
    run.phase = "finalize_run"
    run.stop_reason = "patches_downloaded"
    run.summary_json = {"patch_found": True, "patch_count": 1, "runtime_kind": "patch_agent_graph"}
    session.flush()
    return state
```

但这样就失去了端到端验证的价值。更好的做法是保留为集成测试（需要 TEST_DATABASE_URL），在本次收口中先简化为 mock graph 版本。

#### 4.3.2 `test_worker_once_preserves_llm_fallback_summary_when_patch_download_failed`

**删除**：LLM fallback 不再是独立模块。

#### 4.3.3 `test_worker_follows_debian_tracker_chain_to_gitlab_commit_patch`

当前问题：mock `page_fetcher.http_client.get`。这是最有价值的链路追踪端到端测试。

**改写策略**：改为 mock browser bridge，每个 URL 返回对应的 `BrowserPageSnapshot`。这个测试有较高的改写复杂度，建议标记为 `@pytest.mark.skipif(not os.environ.get("TEST_DATABASE_URL"), reason="需要 DB")`，在 Phase 4 集成测试中完善。

### 4.4 test_cve_api.py — 轻微调整

API 测试主要测试视图层，不直接依赖 runtime。大部分测试通过直接设置 DB 记录来验证 API 响应，不需要改动。

**需检查的测试**：

1. `test_get_cve_run_detail_keeps_legacy_progress_contract_for_fast_first_run`（第 441 行）：测试名含 `fast_first`，但实际测试的是 phase=finalize_run 时的进度计算。数据直接写 DB，不依赖 runtime。**保持不变**，但建议重命名为 `test_get_cve_run_detail_keeps_legacy_progress_contract_for_non_agent_run`。

2. `test_get_cve_run_detail_returns_llm_fallback_summary_fields`（第 534 行）：测试 summary_json 透传。数据直接写 DB。**保持不变**（旧记录可能仍有这些字段）。

3. `test_get_cve_run_failed_detail_uses_failed_phase_for_progress`（第 509 行）：使用 `phase = "fetch_page"`。`detail_service.py` 的 `_LEGACY_PHASES` 仍支持此 phase。**保持不变**。

### 4.5 test_platform_*.py 和 test_search_graph_service.py

这些测试使用 `job_type="cve_patch_fast_first"` 仅用于创建 fixture 数据。由于 `worker/runtime.py` 仍兼容此 job type，不需要改动。

---

## 第五部分：验收标准

完成所有改动后，以下命令必须全部通过：

```bash
# 不依赖 DB 的核心测试
timeout 90s ./.venv/bin/python -m pytest \
  backend/tests/test_cve_agent_policy.py \
  backend/tests/test_chain_tracker.py \
  backend/tests/test_browser_agent_llm.py \
  backend/tests/test_browser_infra.py \
  backend/tests/test_canonical.py \
  backend/tests/test_cve_agent_graph.py \
  backend/tests/test_cve_runtime.py \
  -q

# 确认废弃文件已删除
test ! -f backend/app/cve/agent_llm.py
test ! -f backend/app/cve/llm_fallback.py
test ! -f backend/app/cve/page_fetcher.py
test ! -f backend/app/cve/navigation.py
test ! -f backend/app/cve/prompts/patch_navigation.md
test ! -f backend/tests/test_cve_agent_llm.py
test ! -f backend/tests/test_cve_llm_fallback.py
test ! -f backend/tests/test_page_fetcher.py

# 确认生产代码无旧模块引用
! grep -r "from app.cve.agent_llm" backend/app/
! grep -r "from app.cve.llm_fallback" backend/app/
! grep -r "from app.cve.page_fetcher" backend/app/
! grep -r "from app.cve.navigation " backend/app/

# 确认测试代码无旧模块引用
! grep -r "call_agent_navigation" backend/tests/
! grep -r "app.cve.runtime.fetch_page" backend/tests/
! grep -r "app.cve.runtime.analyze_page" backend/tests/
! grep -r "app.cve.runtime.plan_frontier" backend/tests/
! grep -r "app.cve.runtime.maybe_run_cve_llm_fallback" backend/tests/
! grep -r "collect_follow_links" backend/tests/
! grep -r "from app.cve.agent_llm" backend/tests/
! grep -r "from app.cve.llm_fallback" backend/tests/
! grep -r "from app.cve.page_fetcher" backend/tests/
```

---

## 执行顺序建议

1. 先做第一部分（Review 修复），确认不破坏现有通过的测试
2. 做第四部分（测试迁移），使测试不再依赖即将删除的模块
3. 做第二、三部分（删除文件）
4. 跑验收命令
