# Phase 4 开发提示词：集成测试与调优

你正在 `/opt/projects/demo/aetherflow` 仓库中实现 CVE Patch 浏览器驱动型 AI Agent 的 Phase 4。

## 前提

Phase 1/2/3 已全部完成。浏览器 Agent 的完整执行链路已可运行。

## 权威参考

- 设计规格：`docs/superpowers/specs/2026-04-21-cve-browser-agent-design.md`（第 10 节 Phase 4）
- 模块设计：`docs/04-功能设计/M103-CVE数据源与页面探索规则功能设计.md`

## 本轮目标

1. 创建 5 个真实 CVE 场景的集成测试（使用录制的浏览器会话数据）
2. 调优提示词
3. 全量回归

## 交付物

### 1. 集成测试 `backend/tests/test_browser_agent_integration.py`

使用 **录制数据** 模式：不真的调用外部 LLM 或真的打开浏览器访问外网，而是用预录制的 BrowserPageSnapshot 和 LLM 响应做端到端走通。

#### 测试场景 1：CVE-2022-2509（GnuTLS Double Free）

预期链路：NVD advisory → Debian security-tracker → GitLab commit → .patch
- 录制 3 个 BrowserPageSnapshot（NVD 页、Debian tracker 页、GitLab commit 页）
- 录制 3 个 LLM 响应（expand_frontier × 2 + try_candidate_download）
- 验证最终找到 patch URL

#### 测试场景 2：CVE-2024-3094（xz-utils 后门）

预期链路：多链路多域
- 至少 2 条并行链路
- 验证多链路管理和预算分配

#### 测试场景 3：仅有 GitHub commit 引用的 CVE

预期链路：NVD → GitHub commit → append .patch
- 最短链路（1-2 跳）
- 验证 reference_matcher 直达识别

#### 测试场景 4：无 patch 可达的 CVE

预期结果：所有链路进入 dead_end，收口为 `no_viable_frontier`
- 验证停止条件可解释性

#### 测试场景 5：预算耗尽

预期结果：搜索预算耗尽时正确收口
- 设置极低预算（max_pages_total=3）
- 验证收口为 `search_budget_exhausted`

### 2. 录制数据夹具 `backend/tests/fixtures/browser_agent/`

```
backend/tests/fixtures/browser_agent/
    cve_2022_2509/
        snapshot_nvd.json           # BrowserPageSnapshot 序列化
        snapshot_debian_tracker.json
        snapshot_gitlab_commit.json
        llm_response_1.json         # LLM 决策响应
        llm_response_2.json
        llm_response_3.json
    cve_2024_3094/
        ...
    ...
```

每个 snapshot JSON 必须是 BrowserPageSnapshot 可反序列化的格式。LLM 响应必须符合输出 Schema。

### 3. 提示词调优

基于测试结果调优 `backend/app/cve/prompts/browser_agent_navigation.md`：

- 如果 LLM 在 tracker 页面不选择跨域 commit 链接：强化"典型链路模式"部分
- 如果 LLM 过早停止：强化"所有活跃链路终止前不得 stop_search"
- 如果 LLM 选择无关链接：强化"只能从 key_links 列表中选择"

### 4. 全量回归

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

## 验收标准

1. 5 个集成测试场景全部通过
2. CVE-2022-2509 场景：通过 Debian tracker → GitLab commit 链路找到 patch URL
3. 所有现有回归测试通过
4. 无 import 错误（废弃文件已全部清理）

## 约束

- 所有代码注释使用简体中文
- 录制数据必须手工构造（不从外网实时抓取），确保测试可离线运行
- 不修改 DB schema
- 集成测试不依赖真实 LLM 服务或外网访问
