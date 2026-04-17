# CVE 运行详情与补丁证据功能设计

> **CVE 详情页详细功能设计文档**

---

## 📋 模块概述

**模块名称**：CVE 运行详情与补丁证据  
**模块编号**：M102  
**优先级**：P0  
**负责人**：AI + 开发团队  
**状态**：最小闭环已落地

---

## 🎯 功能目标

### 业务目标
提供一个“可解释”的运行详情页，完整展示一次 CVE run 的结论、进度、来源证据、fix family 概览、patch 列表和 diff。

### 用户价值
- 用户不仅知道有没有补丁，还知道系统是如何找到补丁的。
- 可以在详情页里直接完成复核，而不必回外部站点逐一打开。
- 即使运行失败，也能看到失败阶段、最近进展与来源证据。

---

## 👥 使用场景

### 场景1：复核主补丁
**场景描述**：用户想确认系统标记的主补丁是否可信。

**用户操作流程**：
1. 打开 `/cve/runs/{run_id}`
2. 查看主结论卡片
3. 查看主 patch 和来源证据
4. 打开 diff 内容核查

### 场景2：查看页面探索过程
**场景描述**：用户想知道系统为什么从某个公告页跳到某个 patch 链接。

**用户操作流程**：
1. 在详情页查看 trace timeline
2. 查看步骤摘要
3. 查看 `status`、`url`、`error_message` 和 `stop_reason`

---

## 🔄 业务流程

### 主流程

```mermaid
flowchart TD
    A["进入 /cve/runs/run_id"] --> B["加载 run 完整数据"]
    B --> C{"run 存在？"}
    C -->|否| D["展示空态\n允许返回"]
    C -->|是| E["展示结论卡片\nstop_reason / 主判据"]
    E --> F["展示 Fix Family 概览\n来源页 / 聚合补丁数"]
    F --> G["展示 Patch 列表\n下载状态 / 重复记录数"]
    G --> H["展示 Trace 时间线\n页面探索过程"]
    H --> I{"用户点击查看 diff？"}
    I -->|是| J["按需加载 diff 内容"]
    I -->|否| K["保持当前视图"]
```

---

## 📊 功能清单

| 功能点 | 功能描述 | 优先级 | 状态 |
|--------|---------|--------|------|
| 结论卡片 | 展示是否命中主补丁、主要依据 | P0 | ✅ 已完成 |
| Fix Family 概览 | 按来源页聚合 patch 候选并给出主阅读入口 | P0 | ✅ 已完成 |
| Patch 列表 | 展示候选补丁、下载状态与重复记录数 | P0 | ✅ 已完成 |
| Diff 查看 | 在线查看补丁内容 | P0 | ✅ 已完成 |
| Trace 时间线 | 展示页面探索过程 | P0 | ✅ 已完成 |
| 失败态进度 | 展示真实失败阶段与完成步数 | P0 | ✅ 已完成 |
| 受限 LLM fallback 提示 | 仅在详情页展示建议层与审计提示 | P1 | 🚧 待实现 |

---

## 🎨 界面设计

### 页面1：CVE 运行详情页
**页面路径**：`/cve/runs/:runId`

**页面元素**：
- 顶部结论卡片
- fix family 概览区块
- diff 查看器
- patch 列表区块
- trace 时间线

**交互说明**：
- 点击 patch：按稳定的 `patch_id` 选中当前 patch
- 点击“查看 Diff”：按需加载文本内容
- patch 内容不存在时，按钮不可点
- fix family 概览只做聚合表达，不替代 patch 明细列表
- trace 默认展示整理后的步骤摘要

---

## 🗺️ 页面映射

- 主页面规格：`../13-界面设计/P102-CVE运行详情页面设计.md`
- 上游工作台：`../13-界面设计/P101-CVE检索工作台页面设计.md`
- 视觉基线：`../13-界面设计/U002-视觉基线与继承策略.md`

**页面边界**：
- 本模块负责详情接口、patch 与证据数据对象。
- `P102` 负责“结论 -> Family -> Diff Viewer -> Patch -> Trace”的页面排序。

---

## 💾 数据设计

### 涉及的数据表
- `cve_runs`
- `cve_patch_artifacts`
- `artifacts`
- `source_fetch_records`

### 核心数据字段

#### CVERunDetail
| 字段名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| run_id | string | 是 | 运行 ID |
| cve_id | string | 是 | CVE 编号 |
| status | string | 是 | 状态 |
| phase | string | 是 | 当前阶段 |
| stop_reason | string | 否 | 停止原因 |
| summary | object | 是 | 运行摘要 |
| progress | object | 是 | 阶段进度摘要 |
| fix_families | array | 是 | 来源页聚合视图 |
| recent_progress | array | 是 | 最近 1 到 3 条进展 |
| patches | array | 是 | 补丁记录 |
| source_traces | array | 是 | 页面探索证据 |

补充说明：

- `summary` 当前除规则链摘要外，还预留承载第一版 LLM fallback 审计字段
- 第一版建议字段最小集合为：
  - `llm_fallback_triggered`
  - `llm_trigger_reason`
  - `llm_invocation_status`
  - `llm_decision`
  - `llm_confidence_band`
  - `llm_reason_summary`
  - `llm_model`
  - `llm_provider`
  - `llm_verdict_source`
  - `llm_input_candidate_count`
  - `llm_input_source_count`
  - `llm_selected_candidate_key`
  - `llm_selected_candidate_url`
- 上述字段只表达“受限建议层”的结论，不改写 `patch_found`、`patch_count`、`primary_patch_url` 或 run 的成败终态

#### CVEFixFamilyView
| 字段名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| family_key | string | 是 | 当前 run 内的稳定家族键 |
| title | string | 是 | 当前 family 标题 |
| source_url | string | 是 | 发现该 family 的来源页 |
| source_host | string | 是 | 来源 host |
| discovery_rule | string | 是 | `matcher/bugzilla_attachment/unknown` |
| patch_count | number | 是 | 当前 family 中的 patch 数量 |
| downloaded_patch_count | number | 是 | 下载成功数量 |
| primary_patch_id | string | 是 | 当前代表 patch |
| patch_ids | array | 是 | family 内 patch 列表 |
| patch_types | array | 是 | family 内 patch 类型去重结果 |
| evidence_source_count | number | 是 | 当前 family 关联的来源数量 |
| related_source_hosts | array | 是 | 关联来源 host 去重结果 |
| evidence_sources | array | 是 | 关联来源最小审计列表 |

#### CVEPatchView
| 字段名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| patch_id | string | 是 | 稳定补丁标识 |
| candidate_url | string | 是 | 候选 patch URL |
| patch_type | string | 是 | `patch/diff/debdiff/github_pull_patch/gitlab_commit_patch/gitlab_merge_request_patch/kernel_commit_patch/bugzilla_attachment_patch` 等 |
| download_status | string | 是 | 下载状态 |
| artifact_id | string | 否 | 关联 Artifact |
| duplicate_count | number | 是 | 同 URL 的落表记录数 |
| content_available | boolean | 是 | 是否允许查看 diff |
| content_type | string | 否 | Artifact 内容类型 |
| download_url | string | 否 | 真实下载地址 |

---

## 🔌 接口设计

### 接口1：获取运行详情
**接口路径**：`GET /api/v1/cve/runs/{run_id}`

**业务规则**：
- 直接返回详情页所需完整 payload
- `fix_families` 只表达当前来源页聚合结果，不代表已落地 graph runtime
- `fix_families.source_url` 既可能是 advisory / 公告页，也可能是 seed 中直接命中的 commit / patch 引用
- `fix_families.evidence_sources` 用于表达“同一 fix 还有哪些来源也共同指向它”
- `patches` 已按 `candidate_url` 去重，并返回 `duplicate_count`
- `source_traces` 中的 `cve_seed_resolve` 会暴露 `response_meta.source_results`
- 前端应通过展示层把新增 `patch_type` 转成可读标签
- 当 `summary.llm_fallback_triggered = true` 时，详情页可以展示轻量建议与审计提示，但不得把该建议渲染成新的主结论

### 接口2：获取补丁内容
**接口路径**：`GET /api/v1/cve/runs/{run_id}/patch-content?patch_id=...`

**业务规则**：
- 补丁内容按需加载
- 如果 Artifact 不存在，返回 404
- 优先按稳定 `patch_id` 读取内容
- 为兼容历史调用，接口仍可接受 `candidate_url`
- 如果同一 `candidate_url` 存在多条记录，按“代表条目”读取可消费内容

---

## 📦 前端状态对象

#### PatchDiffPanelState
| 字段名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| patch_id | string | 否 | 当前查看的补丁标识 |
| loading | boolean | 是 | 是否正在加载 diff |
| content_available | boolean | 是 | 是否存在 diff 内容 |
| error_message | string | 否 | diff 加载失败提示 |

---

## 🔁 子流程/状态机

### 详情页与 Diff 查看状态机
```text
detail_loading
  -> detail_ready
  -> detail_empty

detail_ready
  -> diff_idle
  -> diff_loading
  -> diff_ready
  -> diff_failed
```

**状态说明**：
- 详情页加载与 diff 加载分成两个状态机，避免局部失败拖垮整页。
- `detail_empty` 用于无效 `run_id` 或结果不存在场景。

---

## ✅ 业务规则

### 规则1：先给结论，再给证据
**规则描述**：详情页顶部必须先说明主结论，而不是先显示调试数据。

### 规则2：当前只实现最小 fix family 视图
**规则描述**：当前 `fix_families` 只按来源页聚合 patch 候选，用于增强详情页可解释性；不引入 family 持久化表，也不等价于 graph runtime。

### 规则3：证据链可读性优先
**规则描述**：trace 不只是原始 JSON，要整理为人类可读的时间线与步骤原因。

### 规则4：重复 patch 只展示代表条目
**规则描述**：相同 `candidate_url` 的重复记录不重复出卡，而是合并为一条，并通过 `duplicate_count` 暴露重复数量。

### 规则5：`content_available` 必须反映真实可读性
**规则描述**：只有 Artifact 行存在且磁盘文件仍存在时，按钮才允许查看 diff。

### 规则6：详情页内部交互优先使用稳定标识
**规则描述**：前端选中补丁和读取 diff 时优先使用 `patch_id`，避免依赖 `candidate_url` 这种业务键。

### 规则7：失败排障必须给出最短阅读路径
**规则描述**：失败 run 的详情页应先给停止原因，再给建议动作和最近失败步骤，避免要求用户自己从整条 trace 里排查。

### 规则8：详情页必须保留来源级 seed 可解释性
**规则描述**：对于 `cve_seed_resolve` trace，详情页不能只展示合并后的引用数，还必须允许前端消费每个来源的 `status`、`status_code` 与 `reference_count`。

### 规则9：family 只是聚合视图，不替代 patch 明细
**规则描述**：详情页仍以 `patches` 作为可交互明细列表，family 只负责帮助用户快速理解“这些 patch 是从哪类来源页发现的”。

### 规则10：family 来源既可以是页面，也可以是 seed 直达候选
**规则描述**：如果 patch 是直接从 seed 中的 commit / patch / diff 引用命中的，详情页允许把该引用自身作为 family `source_url` 展示，而不是强制要求存在中间页面。

### 规则11：family 必须保留多来源共指的最小审计信息
**规则描述**：当前详情页不做 graph runtime，但 `fix_families` 必须能表达同一 fix 被多个来源共同指向的最小来源列表，用于解释规则链路为何收敛到该 patch。

### 规则12：LLM fallback 在详情页中只属于建议层
**规则描述**：详情页可以展示“受限 LLM 建议优先人工复核哪个已有候选”或“建议人工复核现有来源链路”，但不得把该建议表现为新的主 patch 结论。

### 规则13：详情页必须区分规则结论与 LLM 建议来源
**规则描述**：当存在 LLM fallback 时，页面必须通过来源标记或文案明确其属于 `llm_fallback`，避免用户误以为规则链已经下载成功补丁。

---

## 🚨 异常处理

### 异常1：run 不存在
**触发条件**：通过无效 run_id 打开详情页

**错误提示**：`运行记录不存在`

**处理方案**：展示空态并允许返回工作台

### 异常2：diff 内容缺失
**触发条件**：patch 记录存在，但 Artifact 丢失或下载失败

**错误提示**：`补丁内容不存在或尚未下载`

**处理方案**：保留 patch 元数据，标记内容不可查看

---

## 🔐 权限控制

### 访问权限
- v1 全局可见

### 数据权限
- 单租户共享详情结果

---

## 📝 开发要点

### 技术难点
1. trace 与 patch 信息都来源于运行链路，但必须按“结论优先”拆开组织。
2. diff 内容可能很长，需要按需加载和懒渲染。
3. 旧数据中可能存在重复 patch URL，需要在详情服务层合并。

### 性能要求
- 详情接口响应目标 < 500ms
- diff 内容接口按需加载，避免首页一次返回大文本

### 注意事项
- 详情页是“证据页”，不是“原始 JSON 页”
- 原始字段可以保留为开发辅助，但不能是主视图

---

## 🧪 测试要点

### 功能测试
- [x] 详情页能展示主结论
- [x] patch 列表能展示下载状态
- [x] diff 查看可按需加载
- [x] 重复 `candidate_url` 只展示一条代表记录，并返回 `duplicate_count`
- [x] 详情接口能暴露 `source_results` 与新增 `patch_type`

### 边界测试
- [x] 无效 run_id 显示空态
- [x] 无 diff 内容时显示明确提示
- [x] 失败 run 显示真实失败阶段与完成步数

---

## 📅 开发计划

| 阶段 | 任务 | 预计工时 | 负责人 | 状态 |
|------|------|---------|--------|------|
| 设计 | 完成详情页设计 | 0.5天 | AI | ✅ |
| 开发 | 详情数据接口 | 1天 | AI | ✅ |
| 开发 | 前端详情页与 diff 查看 | 1.5天 | AI | ✅ |
| 测试 | 详情与异常路径测试 | 1天 | AI | ✅ |

---

## 📖 相关文档

- `M101-CVE检索工作台功能设计.md`
- `M103-CVE数据源与页面探索规则功能设计.md`
- `../13-界面设计/P102-CVE运行详情页面设计.md`

---

## 🔄 变更记录

### v1.0 - 2026-04-09
- 初始化 CVE 运行详情与证据设计

### v1.1 - 2026-04-09
- 回填详情页页面映射、Diff 状态对象与双层状态机

### v1.2 - 2026-04-13
- 回填本轮最小闭环真实实现，移除未落地的 fix family / `/patches` 接口描述
- 增加失败进度、代表条目、`duplicate_count` 和真实 `content_available` 契约
- 同步来源证据 `source_fetch_records` 的详情页消费方式

### v1.3 - 2026-04-15
- 把详情页补丁交互从 `candidate_url` 收敛为稳定的 `patch_id`
- 同步 diff 内容接口、详情 payload 和前端状态对象

### v1.4 - 2026-04-15
- 增加失败详情页的排障表达约束：建议动作、错误摘要和失败步骤强调
- 明确失败 run 详情应先给最短阅读路径，再给完整 trace

### v1.5 - 2026-04-15
- 同步官方优先多源 seed trace 已进入详情 payload
- 扩充 `patch_type` 取值说明，覆盖 Debdiff、GitHub、GitLab、Kernel、Bugzilla 等类型
- 明确详情页展示层需要对新增类型做可读文案映射

### v1.6 - 2026-04-16
- 新增最小 `fix_families` 聚合视图，用来源页维度组织 patch 候选。
- 明确当前 family 只是详情聚合层增强，不是已落地 graph runtime 或 family 持久化模型。

### v1.7 - 2026-04-16
- 同步 family 来源既可能来自 advisory 页面，也可能来自 seed 直达 commit / patch 引用。
- 补充 direct seed candidate 场景下的详情页展示边界。

---

**文档版本**：v1.7
**创建日期**：2026-04-09  
**最后更新**：2026-04-16
**维护人**：AI + 开发团队
