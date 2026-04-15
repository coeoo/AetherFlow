# 2026-04-10 Session009 - Phase 2 平台底座 Spec 与实施计划收口

状态: ✅ 已完成

## 做了什么

- 重新复核当前仓库本地事实，确认 Phase 0 与 Phase 1 已完成，Phase 2 尚缺专用 spec 与 implementation plan。
- 根据 review 指出的三处契约冲突，重新收口 Phase 2 的边界：
  - Phase 2 不开放依赖 `scene_run_id` 的任务中心对外接口
  - `/health/summary` 缩成最小字段集，并写死 heartbeat TTL 规则
  - Artifact 与 attempt 的关系通过 `task_attempt_artifacts` 关联表表达，不污染 `artifacts` 主表
- 新增 Phase 2 专用设计文档与实施计划。
- 回写数据库设计、模块设计和页面规格，消除新 spec 与旧文档的双口径。

## 本次更新的文档

- `docs/03-系统架构/数据库设计.md` — 新增 `task_attempt_artifacts`、`runtime_heartbeats` 契约
- `docs/04-功能设计/M002-平台任务执行与调度中心功能设计.md` — 明确 Phase 2 不开放依赖 `scene_run_id` 的任务接口
- `docs/04-功能设计/M004-公共文档采集与Artifact基座功能设计.md` — 明确 Artifact 中立语义与 attempt 关联表方案
- `docs/04-功能设计/M005-平台系统配置与健康观测功能设计.md` — 收口 health summary 字段与 heartbeat 判级规则
- `docs/13-界面设计/P002-平台任务中心页面设计.md` — 把真实数据态延期到 3A+
- `docs/13-界面设计/P005-平台系统状态页面设计.md` — 去掉 Phase 2 不落地的 `enabled_sources` / `enabled_channels`
- `docs/superpowers/specs/2026-04-10-phase2-platform-foundation-design.md` — 新增 Phase 2 设计收口文档
- `docs/superpowers/plans/2026-04-10-phase2-platform-foundation.md` — 新增 Phase 2 实施计划

## 本次更新的代码

- 无业务代码改动

## 关键决策

- `task_job` 的产品契约保持不变：它仍然只表达带真实场景 `run` 的执行；Phase 2 只是暂不开放依赖该契约的对外查询接口。
- Phase 2 允许测试夹具在真实 PostgreSQL 中预置 `task_jobs` 样本，用于验证 runtime 闭环，但这不构成产品级写接口。
- `artifacts` 继续保持 canonical content store 的中立语义，attempt 归属通过 `task_attempt_artifacts` 关联表表达。
- 系统页的最小健康摘要固定为 `api / database / worker / scheduler / notes`，`enabled_sources / enabled_channels` 明确延期。

## 问题与处理

- 问题：上一版方案同时推进 `/platform/tasks` 和“测试直接写 `task_jobs`”会与 `task_job -> scene_run` 契约冲突。
- 处理：把公共任务接口整体延期到 3A+，Phase 2 只保留 runtime-private 能力和测试夹具。

- 问题：`P005` 页面规格比 `M005` 模块契约多出了 `enabled_sources / enabled_channels`，实现阶段会临场扩需求。
- 处理：把系统页收口为最小健康摘要，延期这两个字段到监控/投递阶段。

- 问题：如果直接给 `artifacts` 增加 `producer_attempt_id`，会把共享内容模型悄悄改成运行时归属模型。
- 处理：改为 `task_attempt_artifacts` 关联表方案，并同步回写数据库设计与 M004。

## 验证与证据

- 隔离 worktree：`.worktrees/phase2-foundation-docs`
- 基线工作树状态：干净
- baseline 测试：

```bash
TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev \
timeout 60s ./.venv/bin/python -m pytest \
  backend/tests/test_app_boot.py \
  backend/tests/test_runtime_entrypoints.py \
  backend/tests/test_migrations.py -q
```

结果：

- 首次在新 worktree 中失败，原因是 worktree 下缺少 `.venv/bin/alembic`
- 运行 `timeout 60s bash scripts/bootstrap_backend_env.sh` 后重试通过
- 最终结果：`7 passed`

## 下次计划

1. 以 `docs/superpowers/specs/2026-04-10-phase2-platform-foundation-design.md` 为准进入实现。
2. 严格按 `docs/superpowers/plans/2026-04-10-phase2-platform-foundation.md` 的 TDD 顺序推进。
3. 真实 PostgreSQL 验证通过前，不宣称 Phase 2 已完成。

## 遗留风险

- 当前只完成了 spec 与 plan 的收口，还没有进入代码实现。
- `task_job -> scene_run` 的第一条真实产品级写路径仍然留待 3A 处理，后续实现时必须防止把测试夹具误包装成公共接口。
