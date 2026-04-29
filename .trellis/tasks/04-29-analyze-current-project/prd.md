# 分析当前项目

## Goal

使用 Trellis 流程对当前仓库做一次项目分析，建立关于整体架构、核心业务链路、关键入口、工作区热点改动和当前阶段状态的清晰认识；若分析中发现明确、低风险的口径不一致，则做最小修正。

## What I already know

* 当前仓库是 Trellis 管理项目，存在 `.trellis/workflow.md`、`.trellis/spec/` 和任务系统。
* 当前会话开始时没有 active task，现已创建并启动 `04-29-analyze-current-project`。
* 当前分支为 `main`，工作区存在未提交改动。
* 这是一个单仓库项目，规范层包含 `backend` 与 `frontend`。

## Assumptions (temporary)

* 本次需求最初是“分析当前项目”，当前已追加一个最小实现项：把首页场景配置中的 CVE path 从旧口径同步为 `/patch`。
* 结论应优先基于当前本地代码事实，而不是文档假设。
* 如文档与代码不一致，需要明确区分“文档描述”与“代码现状”。

## Open Questions

* 当前项目的真实主链路是否仍以平台底座、CVE Patch Agent、公告监控三条线为主。
* 当前未提交改动主要集中在哪些模块，以及它们对现状判断的影响有多大。

## Requirements (evolving)

* 给出项目技术栈、分层结构和主要目录职责。
* 识别至少一个后端入口和一个前端入口。
* 梳理关键业务链路与重要横切机制。
* 核对当前工作区改动热点，并说明潜在风险。
* 对明确确认的首页场景路径口径不一致做最小修正，使后端配置与前端真实路由同步为 `/patch`。

## Acceptance Criteria (evolving)

* [ ] 给出项目整体结构与主要入口文件。
* [ ] 说明至少一条真实业务链路及其关键模块。
* [ ] 列出当前工作区未提交改动的重点区域。
* [ ] 明确指出代码事实与文档描述的边界。
* [ ] 首页场景配置中的 CVE path 已与前端真实路由同步为 `/patch`。

## Definition of Done (team quality bar)

* 结论可追溯到实际代码入口、服务或路由文件
* 工作区状态已核对
* 关键风险和未确认项已显式标注

## Out of Scope (explicit)

* 不运行写入型命令
* 不做外部资料检索，除非本地上下文不足
* 不扩大到无关重构或批量路径改名

## Technical Notes

* Task 路径：`.trellis/tasks/04-29-analyze-current-project/`
* 工作流入口：`.trellis/workflow.md`
* 规范索引：`.trellis/spec/backend/index.md`、`.trellis/spec/frontend/index.md`
