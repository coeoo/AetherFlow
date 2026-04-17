# CVE 数据源与页面探索规则功能设计

> **CVE 数据处理主链详细功能设计文档**

---

## 📋 模块概述

**模块名称**：CVE 数据源与页面探索规则  
**模块编号**：M103  
**优先级**：P0  
**负责人**：AI + 开发团队  
**状态**：Phase A 已落地，待继续演进

---

## 🎯 功能目标

### 业务目标
定义 CVE 场景的真实后端主链：多源 seed 解析、frontier 规划、seed 直达候选优先消费、页面抓取、规则匹配、单页特化提取、patch 下载与 stop reason 生成。

### 用户价值
- 用户看到的补丁结果不是“黑盒猜出来的”，而是沿当前可信数据源和页面规则推导出来的。

---

## 👥 使用场景

### 场景1：标准 CVE 补丁查询
**场景描述**：针对常规 CVE，从当前支持的数据源获取参考并沿页面继续探索。

### 场景2：复杂 vendor 页面链路
**场景描述**：需要经过 Debian BTS、GitHub/GitLab commit、kernel stable、Bugzilla 附件等路径才能拿到 patch。

---

## 🔄 业务流程

### 主流程

```mermaid
flowchart TD
    A["输入 CVE ID"] --> B["resolve_seeds\n官方优先多源聚合"]
    B --> C{"有 seed references？"}
    C -->|否| D["终止\nstop_reason = no_seed_references"]
    C -->|是| E["plan_frontier\n拆分 direct candidates + page frontier"]
    E --> F["优先收集 seed 中的 direct patch/commit 候选"]
    F --> G["fetch_page\n仅抓取普通页面"]
    G --> H["analyze_page\n规则匹配 + Bugzilla 单页提取"]
    H --> I["合并 direct candidates 与 page candidates"]
    I --> J{"命中显式 patch 候选？"}
    J -->|是| K["download_patches\n下载并生成 Artifact"]
    J -->|否| N1["终止\nstop_reason = no_patch_candidates\n或 fetch_failed"]
    K --> N["finalize_run\n生成 stop_reason 与 summary"]
```

---

## 📊 功能清单

| 功能点 | 功能描述 | 优先级 | 状态 |
|--------|---------|--------|------|
| Seed 解析 | 当前从 `cve_official -> osv -> github_advisory -> nvd` 聚合 seed，并记录来源级 trace | P0 | ✅ 已完成 |
| Frontier 规划 | 当前最小一跳规划，已支持 direct patch candidate 过滤、去重和页面预算限制 | P0 | ✅ 已完成 |
| 规则匹配 | 当前命中 `.patch` / `.diff` / `.debdiff` / `patch=` / GitHub / GitLab / kernel stable | P0 | ✅ 已完成 |
| 单页特化提取 | 当前支持 Bugzilla detail 页 raw attachment | P0 | ✅ 已完成 |
| 内容下载与校验 | 下载 patch 并校验不是 HTML 页面 | P0 | ✅ 已完成 |
| 平台状态对齐 | run 与 job/attempt 终态对齐 | P0 | ✅ 已完成 |
| 多源聚合 | `cve_official`、OSV、GitHub Advisory、NVD 已落地 | P0 | ✅ 已完成 |
| Trace 落表与 frontier 治理 | `source_fetch_records` 已接入 seed/page/download，frontier 已支持高信号优先与单页失败局部容错 | P1 | ✅ 已完成 |
| 受限 LLM 兜底 | 在规则失败或证据不足时做候选选择型建议 | P2 | 🚧 设计已确认，待实现 C1 |

---

## 🎨 界面设计

### 页面1：无独立页面
该模块为后端主链模块，用户通过 `M101` 和 `M102` 间接感知其效果。

---

## 💾 数据设计

### 涉及的数据表
- `cve_runs`
- `cve_patch_artifacts`
- `artifacts`
- `source_fetch_records`

说明：

- 当前真实实现已使用 `cve_runs`、`cve_patch_artifacts`、`artifacts`
- `source_fetch_records` 已接入 CVE 主链，用于记录 seed 解析、页面抓取与 patch 下载 trace
- `cve_fix_families` 不属于本轮已实现范围

### 核心数据字段

#### SourceTraceStep
| 字段名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| url | string | 否 | 当前步骤关联 URL |
| label | string | 是 | 当前步骤的人类可读标签 |
| request_snapshot | object | 是 | 请求快照 |
| response_meta | object | 是 | 响应元数据 |
| error_message | string | 否 | 当前步错误信息 |

说明：

- 当前 API 已返回 `source_traces`
- `cve_seed_resolve` 的 `response_meta` 中已包含 `source_results`
- `cve_seed_resolve` 的 `request_snapshot` 中已包含固定顺序的 `request_urls`

---

## 🔌 接口设计

### 接口1：创建 run
**接口路径**：`POST /api/v1/cve/runs`

### 接口2：获取 run
**接口路径**：`GET /api/v1/cve/runs/{run_id}`

**业务规则**：
- 工作台消费摘要字段
- 详情页消费完整 `source_traces`、`patches` 与 diff 加载入口
- 数据源、frontier 和下载逻辑为场景内部实现

---

## ✅ 业务规则

### 规则1：规则优先于 LLM
**规则描述**：能用显式规则命中 patch 时，不走 LLM；当前仍未接入 CVE 专用 LLM fallback。

### 规则2：LLM 只能做候选选择，不能编造新 URL
**规则描述**：作为后续扩展保留；当前第一轮未实现。

### 规则2.1：C1 第一版只做建议层，不自动补下载
**规则描述**：受限 LLM fallback 的输出只允许写入 `run.summary_json` 作为建议与审计字段，不自动触发再次下载，也不把 run 改写成成功。

### 规则3：停止原因必须明确
**规则描述**：无论成功还是失败，都必须留下 `stop_reason`。

### 规则4：agent 模式下命中的 patch 全部下载
**规则描述**：一旦进入候选列表，不再对已命中的 patch 做数量截断。

### 规则5：普通 HTML 页面不能伪装成 patch 成功
**规则描述**：下载器必须校验响应内容不是 HTML 页面，且正文看起来像真实 patch/diff。

### 规则6：平台任务状态必须与场景 run 终态对齐
**规则描述**：`cve_run = failed` 时，`task_job` / `task_attempt` 也必须收口为失败。

### 规则7：seed 解析必须保留来源级可解释性
**规则描述**：`resolve_seeds` 不只返回合并后的引用，还必须在 trace 中保留固定顺序的 `source_results`、`status_code` 和 `request_urls`。

### 规则8：页面分析必须先 matcher，后单页特化提取
**规则描述**：`analyze_page` 先保留 HTML 中 URL 扫描得到的 matcher 候选，再追加 Bugzilla raw attachment 候选，并按 `urldefrag(candidate_url).url` 去重。

### 规则9：seed 中的 direct patch/commit 候选必须优先于普通页面探索
**规则描述**：`plan_frontier` 必须先从全部 seed references 中识别 `.patch`、`.diff`、GitHub / GitLab commit、kernel patch 等高信号候选，再对剩余普通页面做最小一跳页面规划。

### 规则10：单页抓取失败只能作为局部失败处理
**规则描述**：普通页面抓取失败必须写入 `source_fetch_records`，但只要仍有可分析页面或 direct candidate，就不允许整条 run 立即终止。

### 规则11：当前 `fix_families` 只属于详情聚合视图，不代表已落地 family 持久化或 graph runtime
**规则描述**：当前已实现的是基于 `patch_meta_json` 的 family 视图聚合；`cve_fix_families` 表、graph node / edge 结构和 family 持久化模型都不属于当前代码事实。

### 规则12：C1 fallback 只允许在两个保守触发点后置触发
**规则描述**：第一版只考虑 `no_patch_candidates` 和 `patch_download_failed` 两类收口；不在成功路径、系统异常路径或 `fetch_failed` 这类证据过薄路径中触发。

### 规则13：规则已成功下载补丁时，LLM 不得介入覆盖
**规则描述**：只要规则链已经拿到 `downloaded` patch，或 `summary.primary_patch_url` 已形成，LLM fallback 必须跳过。

### 规则14：C1 的 `no_patch_candidates` 触发只允许给出人工复核建议
**规则描述**：当规则链没有形成任何候选集合时，LLM 不得返回 `select_candidate`；只允许返回 `needs_human_review` 或 `abstain`。

### 规则15：C1 的 `patch_download_failed` 触发只允许在现有 candidate key 白名单内选择
**规则描述**：LLM 只能返回运行时提供的 `canonical_candidate_key`，不能生成新 URL，也不能返回未知 key；URL 必须由运行时根据白名单 key 反查得到。

---

## 🚨 异常处理

### 异常1：无 seed references
**触发条件**：多源查询没有拿到有效引用

**错误提示**：`当前数据源未返回可用参考链接`

**处理方案**：run 终止，`stop_reason = no_seed_references`

---

### 异常1.1：所有 seed 来源都失败
**触发条件**：`cve_official`、`osv`、`github_advisory`、`nvd` 全部失败

**错误提示**：在运行摘要和 trace 中体现为 `resolve_seeds_failed`

**处理方案**：
- `resolve_seed_references` 抛出异常
- `response_meta_json` 仍保留来源级失败结果
- 运行收口为 `stop_reason = resolve_seeds_failed`

---

### 异常2：页面抓取失败
**触发条件**：目标页面访问失败

**错误提示**：在详情页体现为该步抓取失败

**处理方案**：
- 先把失败写入该步 trace
- 只要仍有 direct candidate 或其他成功页面，run 继续向后执行
- 只有在没有可继续消费的页面快照且也没有 direct candidate 时，才收口为 `stop_reason = fetch_failed`
- 如果抓取阶段已经结束，但后续没有形成任何候选，则收口为 `stop_reason = no_patch_candidates`

### 异常3：阶段执行异常
**触发条件**：`resolve_seeds`、`analyze_page`、`download_patches` 等阶段抛出异常

**错误提示**：在运行摘要中能看到明确 `stop_reason` 与 `summary.error`

**处理方案**：
- `cve_run` 必须收口为 `failed/finalize_run`
- 不能停留在 `running`
- Worker 必须同步把平台 `task_job` / `task_attempt` 标记为失败

### 异常4：LLM fallback 调用失败或输出非法
**触发条件**：provider 超时、接口异常、结构化输出非法、返回未知 candidate key

**错误提示**：只在 `summary.llm_invocation_status` 和详情页审计提示中体现

**处理方案**：
- 主链仍按原始 `stop_reason` 收口
- 不允许因为 fallback 失败改变 run 的终态
- 第一版只记录最小审计字段，不扩表

---

## 🔐 权限控制

### 访问权限
- 无独立权限

### 数据权限
- 结果通过场景接口暴露

---

## 📝 开发要点

### 技术难点
1. 需要在“显式规则命中率”和“误把普通页面当 patch”的风险之间做收紧。
2. 多源 seed 已接入后，必须保证来源级 trace 对工作台与详情页仍然可解释。
3. Bugzilla raw attachment 只能做单页特化，不能演进成无边界多跳抓取。

### 性能要求
- 单次 run 必须有整体超时和页面抓取超时
- 同一 run 内要限制 frontier 深度和动态抓取次数
- API 不应为每个请求重复创建新的数据库 Engine / 连接池

### 注意事项
- 不把主链塞回旧 pipeline/stages 目录
- 当前主线不引入 graph run、fix family 持久化或开放式 LLM 代理
- 文档和实现都必须保持“官方记录优先、多源补充、规则优先”的口径
- 测试环境重建 public schema 时，需要避免复用旧缓存连接状态
- C1 fallback 默认关闭，关闭时行为必须完全回退当前基线

---

## 🧪 测试要点

### 功能测试
- [x] 当前官方优先多源 seed 查询可返回初始 references
- [x] 规则可命中 `.patch` / `.diff` / `.debdiff` / GitHub / GitLab / kernel stable URL
- [x] Bugzilla detail 页可提取 raw attachment
- [x] 下载后能生成 patch Artifact
- [x] 普通 HTML commit 页面会被拒绝
- [x] 运行失败时平台任务状态与场景 run 状态对齐
- [x] seed 中的 direct commit / patch 候选会在页面预算之外被优先消费
- [x] 单页抓取失败时，只要仍有其他页面或 direct candidate，run 仍可继续成功

### 边界测试
- [x] 无 reference 时 stop reason 正确
- [x] 所有 seed 来源失败时收口为 `resolve_seeds_failed`
- [x] `resolve_seeds` / `analyze_page` 异常时 run 不会卡在 running
- [x] seed / page / download trace 已落表
- [x] 多源 seed 聚合已落地
- [x] Debian BTS、Bugzilla、Openwall regression fixture 已离线固化
- [x] `fetch_failed` 只在“无其他可继续消费页面且无 direct candidate”时出现
- [ ] 开关关闭时不触发 fallback
- [ ] `no_patch_candidates` 时可触发建议层 fallback
- [ ] `patch_download_failed` 时可触发候选选择型 fallback
- [ ] 已有成功 patch 时不触发 fallback
- [ ] LLM 返回未知 candidate key 时忽略
- [ ] LLM 返回非法结构时忽略
- [ ] provider 异常时维持原有 stop reason 与终态

---

## 📅 开发计划

| 阶段 | 任务 | 预计工时 | 负责人 | 状态 |
|------|------|---------|--------|------|
| 设计 | 完成主链规则设计 | 0.5天 | AI | ✅ |
| 开发 | 官方优先多源 seed 聚合 | 2天 | AI | ✅ |
| 开发 | 非 NVD 规则匹配与单页 Bugzilla 提取 | 2天 | AI | ✅ |
| 开发 | direct seed candidate 优先消费与页面抓取局部容错 | 1天 | AI | ✅ |
| 测试 | 回归样例、异常路径与状态对齐补强 | 1.5天 | AI | ✅ |
| 下一步 | 受限 LLM fallback C1 落地 | 1天 | AI | 🚧 |

---

## 📖 相关文档

- `M101-CVE检索工作台功能设计.md`
- `M102-CVE运行详情与补丁证据功能设计.md`
- `M004-公共文档采集与Artifact基座功能设计.md`

---

## 🔄 变更记录

### v1.2 - 2026-04-15
- 同步 Phase A 已落地事实：官方优先多源 seed、非 NVD 规则库、Bugzilla 单页提取与 regression fixture
- 更新主流程、功能清单、trace 结构、测试要点与下一步边界
- 把旧的“仅 NVD seed / source_fetch_records 未接入”描述修正为当前实现状态

### v1.3 - 2026-04-16
- 同步 Phase B2 已落地：seed 直达 patch/commit 候选优先消费。
- 同步页面抓取改为局部容错，不再被单页失败默认拖死整条 run。
- 收紧 `fetch_failed` 与 `no_patch_candidates` 的收口边界。

### v1.1 - 2026-04-13
- 根据第一轮真实实现更新功能边界
- 明确当前仅支持 NVD seed、显式 patch 规则和 GitHub commit 转 patch
- 补充状态对齐、HTML 伪阳性防护和数据库连接复用约束

### v1.0 - 2026-04-09
- 初始化 CVE 数据源与页面探索设计

---

**文档版本**：v1.3
**创建日期**：2026-04-09
**最后更新**：2026-04-16
**维护人**：AI + 开发团队
