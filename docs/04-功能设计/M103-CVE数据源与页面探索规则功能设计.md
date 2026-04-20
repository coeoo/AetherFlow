# CVE Patch 多跳 Agent 搜索主链功能设计

> **CVE 场景智能体执行内核详细功能设计文档**

---

## 📋 模块概述

**模块名称**：CVE Patch 多跳 Agent 搜索主链  
**模块编号**：M103  
**优先级**：P0  
**负责人**：AI + 开发团队  
**状态**：后端基础能力已落地，主链接线与前端消费待继续推进

---

## 🎯 功能目标

### 业务目标

将 CVE 场景的后端主链从“`fast-first` 规则执行器”升级为“`LangGraph` 编排的受控多跳 Patch Agent”。

新的主链目标不是继续补强关键词匹配，而是：

- 从多源 seed references 出发
- 通过多跳页面探索逐步逼近 patch
- 让模型参与搜索决策，而不是只在失败后做建议层 fallback
- 在有限预算内找到可下载、可校验、可复核的 patch 地址
- 完整保留搜索路径、决策原因、候选收敛和下载验证证据

### 用户价值

- 用户看到的不只是“命中了哪个 patch”，还能看到系统是如何沿多条来源链逐步找到它的。
- 对 bridge page、tracker page、bug tracker、code review 页面等复杂链路，系统可以做受控多跳搜索，而不是只依赖显式关键词命中。
- 即使最终未成功命中 patch，系统也能解释“已经搜索到哪里、为什么停止、还缺什么证据”。

### 模块职责

本模块负责定义 CVE Patch Agent 的正式执行内核：

- 多源 seed 聚合
- 初始 frontier 构建
- 页面抓取与链接提取
- 页面角色识别
- Agent 决策
- 候选下载与校验
- 搜索图落库与证据收敛

---

## 👥 使用场景

### 场景1：标准 CVE Patch 搜索

**场景描述**：用户输入一个 CVE 编号，系统从官方记录、OSV、GitHub Advisory、NVD 等来源拿到初始 references，并在有限预算内搜索 patch。

**目标能力**：

- 优先利用显式 patch 候选
- 若没有显式 patch，则进入多跳页面搜索
- 最终返回 patch 结果或明确的停止原因

### 场景2：安全公告到补丁的桥接链路

**场景描述**：seed 指向的是公告页或 tracker 页，本身不是 patch，需要经过 1 到 4 跳页面探索才能命中 patch。

**典型路径**：

- 公告页 → vendor tracker → bug tracker → raw attachment
- Debian DSA → security tracker → CVE 子页 → GitLab commit patch
- NVD 详情页 → vendor advisory → merge request → `.patch`

### 场景3：复杂 bridge page + 跨域链路

**场景描述**：页面上存在多个“看起来都可能有价值”的普通链接，系统需要在预算内决定：

- 先扩展哪个
- 是否允许跨域
- 哪些节点值得继续深入
- 哪些节点应当剪枝

### 场景4：搜索未收敛但需要解释

**场景描述**：最终没有拿到 patch，但系统必须告诉用户：

- 已访问了哪些页面
- 哪些链接被继续扩展
- 哪些页面被判定为 noise / blocked / bridge
- 为什么在当前预算下停止

---

## 🔄 业务流程

### 长期目标主流程

```mermaid
flowchart TD
    A["输入 CVE ID"] --> B["resolve_seeds\n多源 seed 聚合"]
    B --> C["normalize_and_rank_sources\n标准化来源与初始评分"]
    C --> D["seed_direct_candidate_check\n显式 patch 候选识别"]
    D --> E["build_initial_frontier\n构建首轮 frontier"]
    E --> F["fetch_next_batch\n抓取当前 frontier 页面"]
    F --> G["extract_links_and_candidates\n提取链接、候选和页面特征"]
    G --> H["agent_decide\n模型做搜索决策"]
    H -->|expand_frontier| F
    H -->|try_candidate_download| I["download_and_validate\n下载并校验 patch"]
    I --> J["evaluate_result\n判断是否继续搜索"]
    J -->|continue| F
    J -->|stop| K["finalize_run\n收敛结果与证据"]
    H -->|need_human_review| K
    H -->|stop_search| K
```

### 主流程说明

主流程以图运行时为基础，允许多轮循环决策、frontier 收缩与扩展、候选下载与重新搜索。

---

## 📊 功能清单

| 功能点 | 功能描述 | 优先级 | 状态 |
|--------|---------|--------|------|
| Seed 解析 | 从 `cve_official / osv / github_advisory / nvd` 聚合 seed references，并保留来源级 trace | P0 | 🚧 |
| 直达候选识别 | 识别 seed 中显式 `.patch/.diff/.debdiff` 与 commit / PR / MR patch 候选 | P0 | 🚧 |
| 图运行时编排 | 使用 `LangGraph` 管理状态、节点执行、循环与收口 | P0 | ✅ 已落地基础骨架 |
| Frontier 构建 | 基于来源可信度、页面角色和预算构建初始搜索 frontier | P0 | ✅ 已落地首轮版本 |
| 页面抓取工具 | 受控 HTTP 抓取页面并落 trace / snapshot | P0 | 🚧 |
| 链接与候选提取 | 提取链接、显式候选、页面摘要和规则特征 | P0 | 🚧 |
| 页面角色识别 | 识别 `bridge_page / bug_tracker_page / code_review_page / terminal_patch_page` 等角色 | P0 | 🚧 待接真实页面分析 |
| Agent 决策 | 模型决定扩展哪些链接、是否跨域、何时停止或进入下载 | P0 | 🚧 已落地状态机分支，待接真实决策输入 |
| 预算控制 | 限制总页面数、深度、并行 frontier、跨域扩展与下载尝试 | P0 | ✅ 已落默认预算对象，待接运行时消耗 |
| 候选下载与校验 | 下载 patch、校验内容不是 HTML 且确实像 patch/diff | P0 | 🚧 |
| 搜索图落库 | 持久化搜索节点、边、决策和候选收敛过程 | P0 | ✅ 已落地后端模型与服务层 |
| 详情页图回放 | 展示搜索路径、frontier、budget、决策记录 | P1 | 🚧 已接后端详情字段，前端待完整消费 |
| 人工复核挂点 | 支持在预算耗尽或证据冲突时转人工复核 | P1 | 🚧 待实现 |

---

## 🎨 界面设计

### 页面1：无独立页面

本模块是 CVE 场景的后端智能体执行内核，用户通过以下页面间接感知：

- `M101`：工作台结果和运行状态
- `M102`：详情页中的搜索路径、patch 收敛与证据图

### 对前端的影响

当前详情页已具备：

- 运行状态
- patch 列表
- trace 时间线
- diff 查看

未来需要新增：

- 搜索路径图
- 当前 frontier 面板
- Agent 决策记录
- 预算消耗面板
- 从 seed 到 patch 的收敛链

---

## 📌 当前实现快照（2026-04-20）

### 已落地范围

- Patch Agent 状态对象、策略对象、节点骨架、LangGraph 图入口已创建
- 搜索图相关数据库表、Alembic 迁移、服务层写入接口已创建
- `detail_service` 已返回：
  - `search_graph`
  - `frontier_status`
  - `decision_history`
- `detail_service` 已正确区分：
  - legacy `cve_patch_fast_first`
  - agent `cve_patch_agent_graph`
- 重复命中的候选已支持 evidence merge
- `canonical_key` 已从原始 URL 文本提升为归一化键

### 本轮已验证

已通过以下核心回归：

```bash
TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev \
timeout 60s ./.venv/bin/python -m pytest \
  backend/tests/test_cve_agent_graph.py \
  backend/tests/test_search_graph_service.py \
  backend/tests/test_cve_detail_service.py \
  backend/tests/test_cve_api.py \
  backend/tests/test_cve_agent_schema_contract.py \
  backend/tests/test_migrations.py -q
```

### 下一步实现重点

- 将 `runtime.py` 切到 Patch Agent 主链
- 实现 `extract_links_and_candidates_node`
- 实现 `download_and_validate_node`
- 实现 `finalize_run_node`
- 接 worker / job type 新主线
- 让前端详情页真正展示搜索图、frontier 和决策记录

---

## 💾 数据设计

### 涉及的数据表

#### 当前已存在

- `cve_runs`
- `cve_patch_artifacts`
- `artifacts`
- `source_fetch_records`

#### 目标新增

- `cve_search_nodes`
- `cve_search_edges`
- `cve_search_decisions`
- `cve_candidate_artifacts`

### 平台表职责

#### `cve_runs`

顶层运行记录，承载：

- `status`
- `phase`
- `stop_reason`
- `summary_json`

#### `source_fetch_records`

记录工具级抓取行为，例如：

- seed 解析
- 页面抓取
- patch 下载

它可以继续保留，但不应独自承担图搜索状态的全部表达。

### 目标新增数据模型

#### `cve_search_nodes`

用于表达搜索过程中访问过的页面节点。

| 字段名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| node_id | uuid | 是 | 节点 ID |
| run_id | uuid | 是 | 关联运行 |
| url | string | 是 | 页面 URL |
| depth | number | 是 | 当前节点深度 |
| host | string | 是 | 页面 host |
| page_role | string | 是 | 页面角色 |
| fetch_status | string | 是 | 抓取状态 |
| content_excerpt | string | 否 | 页面摘要 |
| heuristic_features_json | object | 是 | 规则特征摘要 |
| created_at | datetime | 是 | 创建时间 |

#### `cve_search_edges`

用于表达页面之间的跳转关系。

| 字段名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| edge_id | uuid | 是 | 边 ID |
| run_id | uuid | 是 | 关联运行 |
| from_node_id | uuid | 是 | 来源节点 |
| to_node_id | uuid | 是 | 目标节点 |
| edge_type | string | 是 | 边类型 |
| anchor_text | string | 否 | 锚文本 |
| link_context | string | 否 | 链接上下文摘要 |
| selected_by | string | 是 | `rule/agent/human` |
| created_at | datetime | 是 | 创建时间 |

#### `cve_search_decisions`

用于审计 Agent 每一轮决策。

| 字段名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| decision_id | uuid | 是 | 决策 ID |
| run_id | uuid | 是 | 关联运行 |
| node_id | uuid | 否 | 当前决策所处节点 |
| decision_type | string | 是 | 决策类型 |
| model_name | string | 否 | 模型名称 |
| input_json | object | 是 | 决策输入 |
| output_json | object | 是 | 决策输出 |
| validated | boolean | 是 | 是否通过校验 |
| rejection_reason | string | 否 | 被拒原因 |
| created_at | datetime | 是 | 创建时间 |

#### `cve_candidate_artifacts`

用于表达候选 patch 的发现、下载和验证结果。

| 字段名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| candidate_id | uuid | 是 | 候选 ID |
| run_id | uuid | 是 | 关联运行 |
| source_node_id | uuid | 否 | 来源页面节点 |
| candidate_url | string | 是 | 候选 URL |
| candidate_type | string | 是 | 候选类型 |
| canonical_key | string | 是 | 规范化唯一键 |
| download_status | string | 是 | 下载状态 |
| validation_status | string | 是 | 内容校验状态 |
| artifact_id | uuid | 否 | 关联 Artifact |
| evidence_json | object | 是 | 来源与收敛信息 |

---

## 🔌 接口设计

### 接口1：创建 run

**接口路径**：`POST /api/v1/cve/runs`

**当前契约**：

- 创建 `task_job + cve_run`
- 返回 `run_id`

**后续约束**：

- 不需要为 Agent 化重写对外入口
- Agent 图运行时在后台执行，不改变工作台入口模式

### 接口2：获取 run 详情

**接口路径**：`GET /api/v1/cve/runs/{run_id}`

**当前契约**：

- 返回 `summary`
- 返回 `progress`
- 返回 `source_traces`
- 返回 `patches`

**目标扩展**：

后续详情接口需逐步增加以下字段：

- `search_graph`
- `search_nodes`
- `search_edges`
- `decision_history`
- `budget_status`
- `frontier_status`

### 接口3：获取 patch 内容

**接口路径**：`GET /api/v1/cve/runs/{run_id}/patch-content`

**约束**：

- 仍按需加载
- 仍由下载成功的 Artifact 提供内容
- Agent 化不改变 patch 内容读取方式

---

## 📦 前端状态对象

### 当前已消费的对象

- `summary`
- `progress`
- `source_traces`
- `patches`

### 目标新增的对象

#### `PatchSearchGraphView`

| 字段名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| nodes | array | 是 | 搜索节点 |
| edges | array | 是 | 搜索边 |
| frontier | array | 是 | 当前 frontier |
| decision_history | array | 是 | 决策记录 |
| budget | object | 是 | 剩余预算 |

#### `PatchBudgetView`

| 字段名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| max_pages_total | number | 是 | 页面总预算 |
| visited_pages | number | 是 | 已访问页面数 |
| max_depth | number | 是 | 最大深度 |
| current_max_depth | number | 是 | 当前最大深度 |
| max_cross_domain_expansions | number | 是 | 跨域预算 |
| used_cross_domain_expansions | number | 是 | 已用跨域预算 |
| max_download_attempts | number | 是 | 下载预算 |
| used_download_attempts | number | 是 | 已用下载预算 |

---

## 🔁 子流程 / 状态机

### Agent 主状态机

```text
queued
  -> resolve_seeds
  -> build_initial_frontier
  -> fetch_next_batch
  -> extract_links_and_candidates
  -> agent_decide
      -> expand_frontier
      -> try_candidate_download
      -> stop_search
      -> need_human_review
  -> finalize_run
```

### 页面节点生命周期

```text
discovered
  -> fetched
  -> analyzed
  -> expanded / pruned / converted_to_candidate
```

### 候选 patch 生命周期

```text
discovered
  -> canonicalized
  -> download_pending
  -> downloaded / download_failed
  -> validated / invalid_content
```

---

## ✅ 业务规则

### 规则1：规则负责工具和约束，模型负责搜索决策

**规则描述**：

- 规则层负责 seed 解析、页面抓取、链接提取、显式 patch 候选识别、canonical URL 转换、下载与校验。
- 模型负责判断页面角色、链接价值、跨域意愿、继续或停止策略。
- 不允许继续让规则直接决定整个搜索主链。

### 规则2：模型不能直接发 HTTP

**规则描述**：

- 模型不直接抓页面
- 模型只输出动作
- 真正的抓取由受控工具层执行

### 规则3：模型不能乱编 URL

**规则描述**：

- 默认只能从当前已提取的链接集合中选择下一跳
- 唯一允许的 URL 变换是调用 canonicalize 工具，把 commit / MR / PR 转为 patch URL

### 规则4：Agent 输出必须结构化并经过校验

**规则描述**：

- 决策输出必须是结构化 JSON
- 决策动作仅允许：
  - `expand_frontier`
  - `try_candidate_download`
  - `stop_search`
  - `need_human_review`
- 任何超预算、越权、未知链接、重复跳转的输出都必须被拒绝

### 规则5：必须使用显式搜索预算

**规则描述**：

默认预算建议为：

- `max_pages_total = 18`
- `max_depth = 4`
- `max_children_per_node = 2`
- `max_parallel_frontier = 4`
- `max_cross_domain_expansions = 6`
- `max_download_attempts = 6`
- `max_agent_iterations = 10`

### 规则6：允许跨域，但必须受控

**规则描述**：

- 不再把“同域”当作硬编码唯一策略
- 跨域扩展必须消耗专门预算
- 是否跨域由模型结合页面角色、来源可信度和剩余预算共同决定

### 规则7：成功 patch 事实不能被模型覆盖

**规则描述**：

- 一旦已有 patch 下载成功并通过内容校验，模型不得覆盖该事实
- 模型只能决定是否继续搜索补充更多证据，不得改写成功结论

### 规则8：Patch 下载必须继续走确定性校验

**规则描述**：

- 下载器必须检查内容不是 HTML
- 必须确认内容像真实 patch / diff
- 模型不允许直接宣布“这是 patch”

### 规则9：页面必须具备角色语义

**规则描述**：

页面至少应支持以下角色：

- `terminal_patch_page`
- `code_review_page`
- `bug_tracker_page`
- `vendor_advisory_page`
- `security_tracker_page`
- `nvd_or_scoring_page`
- `bridge_page`
- `noise_page`
- `blocked_page`

### 规则10：停止必须可解释

**规则描述**：

Agent 停止时必须明确属于以下之一：

- `patches_downloaded`
- `no_seed_references`
- `search_budget_exhausted`
- `no_viable_frontier`
- `patch_download_failed`
- `need_human_review`
- `run_failed`

### 规则11：必须记录搜索图与决策审计

**规则描述**：

- 不能只保留工具级 trace
- 必须能回放“节点、边、决策、候选、预算”的完整过程

### 规则12：文档与实现都必须围绕 Agent 主线组织

**规则描述**：

- 后续开发、测试、接口与页面设计都必须围绕搜索图、预算和决策收敛展开
- 不再把规则流水线作为文档和模块边界的中心叙事

---

## 🚨 异常处理

### 异常1：无 seed references

**触发条件**：多源查询后没有可用初始 references

**处理方案**：

- 运行收口为 `no_seed_references`
- 仍保留来源级 trace

### 异常2：页面抓取失败

**触发条件**：frontier 节点页面访问失败

**处理方案**：

- 节点标记为 `blocked_page`
- 当前分支失败，但不等于整条 run 失败
- 只要还有可扩展 frontier，搜索继续

### 异常3：模型输出非法

**触发条件**：

- 返回未知动作
- 选择了不存在的链接
- 超出预算
- 越权跨域

**处理方案**：

- 决策记录写入 `validated = false`
- 拒绝该输出
- 可重试一次或直接转人工复核

### 异常4：搜索预算耗尽

**触发条件**：页面数、深度、跨域预算、下载预算或 agent 轮次预算耗尽

**处理方案**：

- 收口为 `search_budget_exhausted`
- 返回当前已访问路径和未完成原因

### 异常5：候选下载失败

**触发条件**：候选 patch 无法下载或内容校验失败

**处理方案**：

- 候选记录标记失败原因
- 若预算允许，继续回到搜索
- 若无剩余预算或无新候选，则收口为 `patch_download_failed`

### 异常6：需要人工复核

**触发条件**：

- 页面角色长期不明确
- 规则与模型结论冲突
- 预算将尽但仍未收敛

**处理方案**：

- 收口为 `need_human_review`
- 返回当前证据和建议操作

---

## 🔐 权限控制

### 访问权限

- 当前无独立权限模型

### 数据权限

- 继续通过场景接口暴露
- 图搜索审计属于详情页可见数据的一部分

---

## 📝 开发要点

### 技术难点

1. 需要把当前线性执行器重构为 `LangGraph` 图运行时，同时不破坏现有 `run` / `job` / `attempt` 收口契约。
2. 需要明确模型与规则的边界，避免模型变成无约束浏览代理。
3. 需要在预算、跨域、候选下载、人工复核之间建立可解释的收口策略。
4. 需要将现有 `source_fetch_records` 升级为“工具级 trace + 图级审计”双层观测模型。

### 性能要求

- 单次 run 必须有整体超时
- 单页抓取必须有超时
- Agent 每轮决策必须受 token 与次数预算约束
- 不能为每个请求重复创建新的数据库 Engine / 连接池

### 注意事项

- 不再以“规则页面探索”作为长期叙事中心
- 不能继续把模型永久限制在失败后建议层
- 不能把同域硬编码策略继续当作唯一导航规则
- 文档必须直接围绕最终 Agent 目标组织，避免再次被旧实现叙事拉回去

---

## 🧪 测试要点

### 当前基线需要继续保留

- [x] 多源 seed 聚合可用
- [x] 显式 `.patch/.diff/.debdiff` 与 commit patch 识别可用
- [x] Bugzilla raw attachment 提取可用
- [x] patch 下载与内容校验可用
- [x] 运行终态与平台任务状态对齐

### Agent 化新增测试

- [ ] LangGraph 状态机可在预算内完成多轮搜索
- [ ] Agent 输出非法动作时会被 validator 拒绝
- [ ] 允许跨域但必须消耗跨域预算
- [ ] 页面角色识别可区分 bridge / bug tracker / code review / terminal patch
- [ ] 搜索预算耗尽时返回可解释 stop reason
- [ ] 已有成功 patch 时模型不能覆盖成功事实
- [ ] 搜索图节点、边、决策可正确落库
- [ ] 详情页可回放搜索路径与预算消耗

### 边界测试

- [ ] 初始 seed 为空时收口为 `no_seed_references`
- [ ] 多个 frontier 并存时不会无限扩展
- [ ] 重复链接不会反复访问
- [ ] 候选 URL 规范化后不会重复下载
- [ ] 模型选择不存在的链接时会被拒绝
- [ ] 预算用尽前后 stop reason 一致且可解释

---

## 📅 开发计划

| 阶段 | 任务 | 预计工时 | 负责人 | 状态 |
|------|------|---------|--------|------|
| 设计 | 明确 Agent 化方向并修正文档体系 | 0.5天 | AI | ✅ |
| 阶段1 | 引入 LangGraph 状态机与受控决策节点 | 2天 | AI | ✅ 基础骨架已完成 |
| 阶段1 | 保留并接入现有工具层能力 | 1天 | AI | 🚧 仅完成 seed/frontier 初步接入 |
| 阶段1 | 实现搜索预算与 validator | 1天 | AI | 🚧 预算对象已落地，validator 待接真实模型输出 |
| 阶段2 | 落搜索节点、边、决策与候选收敛数据模型 | 2天 | AI | ✅ 已完成 |
| 阶段2 | 扩展详情接口与前端搜索图展示 | 2天 | AI | 🚧 后端详情已完成，前端展示待继续 |
| 阶段3 | 增加人工复核挂点与恢复机制 | 1天 | AI | ⏳ |

---

## 📖 相关文档

- [总体项目设计.md](/opt/projects/demo/aetherflow/docs/00-总设计/总体项目设计.md)
- [2026-04-20-cve-patch-agent-graph-design.md](/opt/projects/demo/aetherflow/docs/superpowers/specs/2026-04-20-cve-patch-agent-graph-design.md)
- `M101-CVE检索工作台功能设计.md`
- `M102-CVE运行详情与补丁证据功能设计.md`
- `M004-公共文档采集与Artifact基座功能设计.md`

---

## 🔄 变更记录

### 2026-04-20

- 将文档从“CVE 数据源与页面探索规则”整体改写为“CVE Patch 多跳 Agent 搜索主链”
- 将 `LangGraph` 图运行时、Agent 决策、预算模型、搜索图落库和人工复核纳入正式设计范围
- 不再把“规则优先 + 受限 fallback”作为主文档口径
