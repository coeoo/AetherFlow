# 重写 AGENTS 协作规则

## Goal

基于当前仓库真实状态，重写 repo 根目录 `AGENTS.md`，让它从“零散规则片段”收敛为“清晰、短小、只承载 repo 级协作约束和索引”的文档。它应明确当前项目真相、稳定约束、验证边界和相关文档入口，但不重复全局提示词或长篇 Trellis 流程正文。

## What I already know

* 当前 `AGENTS.md` 只覆盖中文提交和 `.env.local` 本地模型配置，信息量不足。
* 仓库已有完整 Trellis workflow：`.trellis/workflow.md`。
* `docs/design/README.md` 已明确：`AGENTS.md` 只放协作规则和索引，不承载长篇模块设计。
* 当前代码真相已能确认：
  * 前端主路由是 `/`、`/patch`、`/announcements`、`/deliveries`、`/system/tasks`、`/system/health`
  * 系统运行角色是 `API / Worker / Scheduler`
  * `Scheduler` 当前只负责 heartbeat 和到期投递处理
* `.gitignore` 已忽略 `.env.local` 和 `backend/results/`

## Assumptions (temporary)

* 用户希望的是“重新梳理并落盘”，不是只给建议。
* 新版 `AGENTS.md` 应该是精简索引型，而不是复制 `.trellis/workflow.md` 的长篇内容。
* 只写当前仓库长期稳定、可核对的规则，不把临时会话策略写成 repo 真理。

## Open Questions

* 是否需要在 `AGENTS.md` 中显式写出更多 CVE 主线阶段性策略，还是只保留长期稳定约束。

## Requirements (evolving)

* 重写 `AGENTS.md` 结构，使其更适合当前仓库。
* 明确 `AGENTS.md` 与 `.trellis/workflow.md`、`docs/design/README.md`、架构文档之间的边界。
* 保留并整理已确认的 repo 级规则：
  * 中文 commit message
  * `.env.local` / `.env.example` / Candidate Judge 配置规则
  * `/patch` 为 CVE 工作台真实路由
  * `backend/results/` 为运行证据目录，默认不提交
  * DB 测试优先显式使用 `TEST_DATABASE_URL` 并带超时
* 不在 `AGENTS.md` 中复制长篇模块设计或过细执行脚本说明。

## Acceptance Criteria (evolving)

* [ ] `AGENTS.md` 已重写为清晰的 repo 级协作文档。
* [ ] 文档中所有关键事实都能在当前仓库代码或文档中定位。
* [ ] 文档边界明确，不与 `.trellis/workflow.md` 或 `docs/design/README.md` 重复失控。

## Definition of Done (team quality bar)

* 结构清楚，便于 AI 与人类快速读取
* 内容以当前仓库事实为准
* 修改范围只限 `AGENTS.md`，除非校验需要极小范围补充

## Out of Scope (explicit)

* 不重写 `.trellis/workflow.md`
* 不修改业务代码
* 不把长期实现设计复制进 `AGENTS.md`

## Technical Notes

* 当前目标文件：`AGENTS.md`
* 关键事实来源：
  * `.trellis/workflow.md`
  * `docs/design/README.md`
  * `docs/03-系统架构/架构设计.md`
  * `frontend/src/app/router.tsx`
  * `backend/app/scheduler/runtime.py`
  * `.gitignore`
