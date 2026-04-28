# Superpowers 决策索引

> 本文件只索引长期有影响的关键决策。详细论证仍以对应 spec、plan、review
> 为准。

## DEC-001：Superpowers 过程资产不替代主文档

- Date: 2026-04-23
- Status: accepted
- Source: `docs/superpowers/README.md`
- Decision: `docs/superpowers/` 只保存阶段性设计、执行计划和评审记录。
- Reason: 过程资产可能包含历史方案、阶段 prompt 和已替代语义，不能作为当前实现唯一入口。
- Consequence: 当前产品和实现定义仍回到 `docs/` 主文档与代码实现。

## DEC-002：CVE Patch 主线采用浏览器驱动型 Browser Agent

- Date: 2026-04-21
- Status: accepted
- Source: `docs/superpowers/specs/2026-04-21-cve-browser-agent-design.md`
- Decision: CVE Patch 获取主链收口为 LangGraph 图 + Playwright 浏览器。
- Reason: 旧 httpx 抓取和 HTML 截断无法稳定理解跨域 patch 链路。
- Consequence: `page_fetcher.py`、旧 `agent_llm.py`、旧 `patch_navigation.md` 等路径逐步废弃或被替代。

## DEC-003：LangGraph 保留为编排层，不迁移到 Agno / CrewAI

- Date: 2026-04-25
- Status: accepted
- Source: `docs/superpowers/specs/2026-04-25-cve-agent-boundary-refactor-design.md`
- Decision: LangGraph 继续承担状态编排和条件路由，Supervisor 保持确定性规则。
- Reason: 当前主要问题是 Tool / Skill / Decision / Evidence 边界不清，而不是编排框架不足。
- Consequence: 重构重点放在边界拆分、baseline 和评估闭环，不引入新的 Agent 框架主链。

## DEC-004：Candidate Judge 必须默认关闭

- Date: 2026-04-25
- Status: accepted
- Source: `docs/superpowers/specs/2026-04-25-cve-agent-boundary-refactor-design.md`
- Decision: Candidate Judge 作为 Phase 2 的最小 LLM-backed Agent，在 feature flag 下接入。
- Reason: 候选判断会影响下载链路和真实样本回归，必须先保留基线行为。
- Consequence: 默认基线行为不启用 Candidate Judge；只有验证候选判断 Agent 时才显式开启。

## DEC-005：重构前置 baseline，后续迭代绑定 failure category

- Date: 2026-04-25
- Status: accepted
- Source: `docs/superpowers/specs/2026-04-25-cve-agent-boundary-refactor-design.md`
- Decision: Phase 0 先建立 baseline，后续每个阶段复跑 baseline；Phase 3 迭代必须绑定失败分类。
- Reason: CVE Browser Agent 真实链路依赖外部页面和 LLM 行为，重构必须防止真实样本回退。
- Consequence: `backend/results/` 保存本地验收产物，但默认不进入版本控制。
