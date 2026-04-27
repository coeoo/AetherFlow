# AI 使用说明

> **AetherFlow AI 开发者必读文档**

---

## 🎯 会话开始前必须阅读

每次会话开始时，按顺序阅读：

1. 本文件
2. [`总体设计`](../00-总设计/总体项目设计.md)（特别注意第 9 章「当前项目约束」）
3. [`技术链设计`](../03-系统架构/技术链设计.md)（特别注意第 13 章「当前仓库实现状态」）
4. [`功能设计`](../04-功能设计/README.md)
5. [`功能模块关系与开发顺序`](../04-功能设计/M901-功能模块关系与开发顺序设计.md)
6. 如果本次任务涉及前端实现，补读 [`前端架构设计`](../03-系统架构/前端架构设计.md)
7. 如果本次任务涉及页面或 UI 评审，补读 [`界面设计`](../13-界面设计/README.md)
8. 如果本次任务涉及 CVE 工作台或详情页，补读 [`M101-CVE检索工作台功能设计`](../04-功能设计/M101-CVE检索工作台功能设计.md)、[`M102-CVE运行详情与补丁证据功能设计`](../04-功能设计/M102-CVE运行详情与补丁证据功能设计.md)、[`P101-CVE检索工作台页面设计`](../13-界面设计/P101-CVE检索工作台页面设计.md)、[`P102-CVE运行详情页面设计`](../13-界面设计/P102-CVE运行详情页面设计.md)
9. `日志/` 目录下最近 1~3 篇日志

---

## 🔄 当前仓库工作方式

本仓库已完成“文档先行”并进入实现阶段，当前工作方式是：

1. 先确认当前 phase、已落地实现和最近日志
2. 再确认总体项目设计与功能设计文档
3. 涉及前端实现时补读前端架构设计
4. 涉及页面时再确认界面设计文档
5. 涉及数据库时确认 SQL、迁移与验证脚本
6. 写实现前先明确验证边界，完成后补齐证据链
7. 每次会话结束必须写日志

---

## 🧊 历史冻结说明

- `日志/` 目录会保留阶段性开发过程记录，其中可能出现旧的 CVE / Patch Agent spec、plan 或重设计表述。
- 这些内容仅用于历史归档与决策追溯，不作为当前实现入口。
- 当前接手时，应优先以本文件列出的主文档链路，以及最近日志中的最新结论为准。
- 如果历史日志中的旧 spec / plan 引用与当前功能设计冲突，以 `docs/` 下的主文档定义为准。

---

## 🧩 CVE Patch Agent 接手要点

- 页面获取主链是 `Playwright + LangGraph + LLM 导航决策`，不是 httpx 页面抓取。
- `httpx` 只保留给 seed API 和 patch 文件下载。
- GitHub commit 下载当前已具备页面 `.patch` / `.diff` 与 GitHub API patch / diff 多策略。
- GitHub PR 下载当前已具备页面 `.patch`、Pull API patch / diff、页面 `.diff` 多策略。
- kernel commit 下载主路径是从 `git.kernel.org` 提取 SHA 后优先走 GitHub API patch / diff，`git.kernel.org` 直连只作最后诊断兜底。
- 如需降低 GitHub 匿名 API 限流和短时失败风险，应配置可选环境变量 `GITHUB_TOKEN`；token 不得写入代码、文档或日志。
- 下载失败需要优先看 `patch_meta_json.error_kind` 和 `source_fetch_records.response_meta_json.attempts` 中的 `strategy / repository / media_type / error_kind`。
- `downloaded` / `failed` 是候选下载终态，图节点不应重复下载终态候选。
- NVD CVSS calculator（`/vuln-metrics/cvss/`）属于导航噪声，不应进入 frontier 或规则 fallback。
- WordPress、WPScan、Trac 插件等非维护范围组件应优先进入“跳过/非行动项”判断，不应默认扩展下载策略。
- CVE Agent Boundary Refactor Phase 1 已完成并通过 mock candidate baseline 对比；Phase 2 Task 2.1 已引入 Candidate Judge 接口但默认关闭，尚未接入主链。
- 下一步是 Phase 2 Task 2.2：在 feature flag 下接入 Candidate Judge；接入前需要重点 review 候选排序/过滤边界，并在 flag on 场景复跑 baseline 对比。
- `acceptance_browser_agent --all` 会串行执行真实浏览器场景，即使使用 `llm-timeout-forced` mock mode 也仍会抓取真实页面和下载 patch；外层建议使用 `timeout 180s`，与 `all_under_3_minutes` 验收语义一致。
- 普通 pytest、轻量脚本和不访问真实浏览器网络链路的验证命令仍使用 `timeout 60s`。
- `backend/results/` 是验收运行产物，默认不提交。

---

## 📋 AI 会话结束前检查项

- [ ] 相关功能设计文档已更新
- [ ] 如果本次涉及页面，`13-界面设计/` 已更新
- [ ] 如果数据库变更，相关 SQL 已更新
- [ ] 本次会话日志已创建
- [ ] 日志中写明本次更新的文档与文件

---

## 📝 日志要求

日志文件统一放在 `日志/` 目录下，命名规则：

```text
YYYY-MM-DD_SessionNNN_任务名.md
```

必须记录：

- 本次做了什么
- 更新了哪些文档/代码
- 做了哪些关键决策
- 下次计划

---

## ⚠️ 特别约束

- 不把旧 `aetherflow.bak` 的 legacy 语义直接搬进新仓
- 不把 `SecurityAnnouncement` 旧脚本结构直接照抄进新仓
- 平台能力和场景能力必须分层

---

## 🔄 变更记录

### v1.0 - 2026-04-09
- 初始化 AetherFlow AI 使用说明

### v1.1 - 2026-04-09
- 把页面级设计文档纳入 UI 相关任务的必读链路
- 增加页面设计更新检查项

### v1.2 - 2026-04-10
- 把前端架构设计纳入前端实现任务的必读链路

### v1.3 - 2026-04-10
- 把工作方式从“文档先行”更新为“文档已完成、按计划推进实现”
- 增加“先确认当前 phase 与已落地实现”的会话接手要求

### v1.4 - 2026-04-13
- 对 CVE 工作台与详情页任务增加 M101/M102、P101/P102 的必读约束
- 使新会话更容易接手当前已落地的最小闭环与证据页行为

### v1.5 - 2026-04-23
- 增加历史冻结说明，明确 AI 开发日志中的旧 spec / plan 引用仅用于追溯
- 避免把阶段性 CVE / Patch Agent 过程资产误读为当前主规范入口

### v1.6 - 2026-04-24
- 补充 CVE Patch Agent 补丁下载稳定化接手要点
- 明确 GitHub 多策略下载、`GITHUB_TOKEN`、内部重试、错误分类和终态候选跳过是当前主链事实

### v1.7 - 2026-04-24
- 补充 kernel commit 下载主路径：`git.kernel.org` commit identity → GitHub API patch / diff
- 明确 `GITHUB_TOKEN` 是可选稳定性增强，不是 API 下载前置条件
- 明确排障优先查看 attempts 中的 `strategy / repository / media_type / error_kind`

### v1.8 - 2026-04-25
- 补充 GitHub PR patch 下载稳定化接手要点：页面 `.patch` 超时后继续尝试 Pull API patch / diff 与页面 `.diff`
- 补充 NVD CVSS calculator 导航噪声规则，避免把评分计算器误当作补丁线索消耗预算
- 明确 20 个真实 CVE 样本验收后的主线：先修真实失败模式，再决定是否扩展下载源
- 明确非维护范围组件跳过机制是后续优先事项之一，避免把 WordPress 类样本误归因为 downloader 缺口

### v1.9 - 2026-04-27
- 补充 CVE Agent Boundary Refactor Phase 1 已完成并通过 baseline 对比，下一步进入 Candidate Judge 默认关闭接口。
- 明确 acceptance `--all` 与普通 pytest 的 timeout 语义不同：真实浏览器 baseline 使用 `timeout 180s`，普通回归仍使用 `timeout 60s`。
- 明确 `backend/results/` 仍是运行产物，默认不提交。

### v1.10 - 2026-04-27
- 补充 Candidate Judge 默认关闭接口已落地，明确下一步是 feature flag 下接入主链并复跑 baseline。

---

**文档版本**：v1.10
**创建日期**：2026-04-09
**最后更新**：2026-04-27
**维护人**：AI + 开发团队
