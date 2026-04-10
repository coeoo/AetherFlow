# Phase 0 Spec Reconciliation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 收口 v1 的 schema 分层、运行拓扑和实施顺序，让后续实现只依赖一套一致规范。

**Architecture:** 本阶段只修改文档、初始化 SQL 和验证脚本，不写业务运行时代码。核心策略是把 `source_fetch_records` 保持为平台域抓取审计表，在 platform core 初始化阶段不对 `announcement_sources` 建硬外键，同时把运行拓扑统一为“逻辑角色可拆分，但 v1 不依赖消息队列和外部调度基础设施”。

**Tech Stack:** Markdown、PostgreSQL 16、`psql`、`rg`、Bash

---

### Task 0: 隔离执行工作区，避免污染当前脏工作树

**Files:**
- Test only: 当前仓库 Git 状态

- [ ] **Step 1: 先确认当前工作树与本阶段目标文件是否重叠**

Run:

```bash
git status --short --branch
git diff --name-only
```

Expected:
- 能明确看到当前工作树是否已经改动了 `docs/00-总设计`、`docs/03-系统架构`、`docs/04-功能设计`、`docs/05-数据库`、`docs/07-部署运维`

- [ ] **Step 2: 为 Phase 0 创建隔离执行工作区**

Recommended path:

```bash
# 先确认一个可作为执行基线的提交或分支；如果当前脏改动就是要保留的基线，
# 先由维护者自行 checkpoint 成一个明确分支/提交，再从该基线创建 worktree。
git worktree add ../aetherflow-phase0-exec -b phase0-spec-fix <BASELINE_REF>
cd ../aetherflow-phase0-exec
```

Rules:
- 后续所有 `git add` / `git commit` 都只在隔离 worktree 中执行
- 如果还没有可用的 `BASELINE_REF`，不要在当前脏工作树里执行 Phase 0 的 commit 步骤
- 如果必须暂时留在当前工作树，只允许做验证和差异比对，禁止执行本计划中的 commit

- [ ] **Step 3: 验证隔离工作区已经准备好**

Run:

```bash
git status --short --branch
pwd
```

Expected:
- 当前目录已经切到隔离 worktree
- 后续 phase 级 commit 不会把主工作树里的历史文档改动一起带进去

### Task 1: 修复平台域对公告域的反向外键依赖

**Files:**
- Create: `scripts/verify_sql_init_order.sh`
- Modify: `docs/05-数据库/sql/2026-04-09_init_platform_core.sql`
- Modify: `docs/05-数据库/sql/README.md`
- Modify: `docs/03-系统架构/数据库设计.md`
- Modify: `docs/07-部署运维/部署手册.md`
- Test: `docs/05-数据库/sql/*.sql` 通过临时 PostgreSQL 16 按文档顺序执行

- [ ] **Step 1: 写出会失败的初始化顺序验证脚本**

```bash
#!/usr/bin/env bash
set -euo pipefail

: "${DATABASE_URL:?DATABASE_URL is required}"

psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f docs/05-数据库/sql/2026-04-09_init_platform_core.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f docs/05-数据库/sql/2026-04-09_init_cve.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f docs/05-数据库/sql/2026-04-09_init_announcement.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f docs/05-数据库/sql/2026-04-09_init_indexes.sql
```

- [ ] **Step 2: 运行脚本，确认当前顺序确实失败**

Run:

```bash
docker run --rm -d --name aetherflow-phase0-pg \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=aetherflow_phase0 \
  -p 55432:5432 postgres:16-alpine

until docker exec aetherflow-phase0-pg pg_isready -U postgres >/dev/null 2>&1; do
  sleep 1
done

export DATABASE_URL=postgresql://postgres:postgres@127.0.0.1:55432/aetherflow_phase0
timeout 60s bash scripts/verify_sql_init_order.sh
```

Expected:
- FAIL
- 失败点出现在 `2026-04-09_init_platform_core.sql`
- 报错原因是 `announcement_sources` 尚未创建，但 `source_fetch_records.source_id` 已试图建立外键

- [ ] **Step 3: 以最小改动修复 SQL 与配套文档**

Update `docs/05-数据库/sql/2026-04-09_init_platform_core.sql` so `source_fetch_records` keeps `source_id` but does **not** create a hard foreign key in platform core:

```sql
CREATE TABLE IF NOT EXISTS source_fetch_records (
    fetch_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scene_name VARCHAR(32) NOT NULL,
    source_id UUID,
    source_type VARCHAR(64) NOT NULL,
    source_ref VARCHAR(256),
    status VARCHAR(32) NOT NULL,
    request_snapshot_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    response_meta_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

Update the docs so they all say the same thing:
- 平台域 migration 不对 `announcement_sources` 建硬外键
- `source_id` 在 v1 是场景侧弱引用字段
- 文档执行顺序保持 `platform_core -> cve -> announcement -> indexes`

- [ ] **Step 4: 重新跑初始化顺序验证，确认修复生效**

Run:

```bash
docker rm -f aetherflow-phase0-pg || true
docker run --rm -d --name aetherflow-phase0-pg \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=aetherflow_phase0 \
  -p 55432:5432 postgres:16-alpine

until docker exec aetherflow-phase0-pg pg_isready -U postgres >/dev/null 2>&1; do
  sleep 1
done

export DATABASE_URL=postgresql://postgres:postgres@127.0.0.1:55432/aetherflow_phase0
timeout 60s bash scripts/verify_sql_init_order.sh
```

Expected:
- PASS
- 验证运行在干净测试库上，而不是复用 Step 2 留下的半成品 schema
- 4 份 SQL 全部执行完成
- PostgreSQL 中存在 `task_jobs`、`source_fetch_records`、`announcement_sources` 等表

- [ ] **Step 5: 提交这一组变更**

```bash
git add scripts/verify_sql_init_order.sh \
  docs/05-数据库/sql/2026-04-09_init_platform_core.sql \
  docs/05-数据库/sql/README.md \
  docs/03-系统架构/数据库设计.md \
  docs/07-部署运维/部署手册.md

git commit -m "docs: reconcile platform schema initialization order" \
  -m "What: remove the platform-core hard FK from source_fetch_records to announcement_sources and align SQL/docs with the ordered init flow.
Why: the previous design made platform initialization depend on an announcement-domain table that did not exist yet.
Validation: timeout 60s bash scripts/verify_sql_init_order.sh"
```

### Task 2: 统一 v1 运行拓扑口径

**Files:**
- Create: `scripts/verify_phase0_spec_consistency.sh`
- Modify: `docs/00-总设计/总体项目设计.md`
- Modify: `docs/03-系统架构/架构设计.md`
- Modify: `docs/07-部署运维/部署手册.md`
- Modify: `docs/04-功能设计/M002-平台任务执行与调度中心功能设计.md`
- Modify: `docs/04-功能设计/M203-安全公告调度运行与结果功能设计.md`
- Test: 通过 `rg` 校验关键文档不再出现互相冲突的拓扑描述

- [ ] **Step 1: 写出会失败的拓扑一致性检查脚本**

```bash
#!/usr/bin/env bash
set -euo pipefail

rg -q "不引入.*消息队列.*外部调度基础设施|不依赖.*消息队列.*外部调度基础设施" docs/00-总设计/总体项目设计.md
rg -q "逻辑角色" docs/03-系统架构/架构设计.md
rg -q "可同进程运行|可拆分.*本地进程|逻辑角色可拆分" docs/03-系统架构/架构设计.md
rg -q "scheduler.*(逻辑角色|entrypoint|保留).*" docs/07-部署运维/部署手册.md
rg -q "scheduler.*(保留入口|entrypoint|heartbeat)" docs/04-功能设计/M002-平台任务执行与调度中心功能设计.md
rg -q "scheduler.*(保留入口|entrypoint|heartbeat)" docs/04-功能设计/M203-安全公告调度运行与结果功能设计.md

if rg -q "Web/API/Worker/Scheduler 分进程运行" docs/03-系统架构/架构设计.md; then
  echo "found forbidden topology wording in architecture doc" >&2
  exit 1
fi

if rg -q "独立调度服务" docs/04-功能设计/M002-平台任务执行与调度中心功能设计.md; then
  echo "found obsolete scheduler wording in M002" >&2
  exit 1
fi

if rg -q "独立调度服务" docs/04-功能设计/M203-安全公告调度运行与结果功能设计.md; then
  echo "found obsolete scheduler wording in M203" >&2
  exit 1
fi
```

- [ ] **Step 2: 运行脚本，确认当前文档存在冲突**

Run:

```bash
timeout 60s bash scripts/verify_phase0_spec_consistency.sh
```

Expected:
- FAIL
- 失败原因是 `架构设计.md` 仍包含“分进程运行”的硬编码表述，且缺少统一的“逻辑角色 / 不依赖外部调度基础设施”口径

- [ ] **Step 3: 修改总设计、架构设计、部署手册和相关模块设计**

Adopt one canonical wording across the docs:

```text
v1 保留 API / Worker / Scheduler 三个逻辑角色。
它们可以在开发环境按调试需要拆成多个本地进程，
但系统不依赖消息队列和外部调度基础设施才能成立。
Phase 2 只要求 API + Worker 真实闭环，
Scheduler 在早期阶段只保留 entrypoint 与 heartbeat。
```

Update:
- `总体项目设计.md`：把“单进程”改成“单机 / 单实例优先，不依赖外部调度基础设施”
- `架构设计.md`：把“分进程运行”改成“逻辑角色可拆分”
- `部署手册.md`：把调试形态和运行前提分开写
- `M002` / `M203`：明确早期阶段的 `scheduler` 只承担保留入口与后续扩展位

- [ ] **Step 4: 重新运行拓扑一致性检查**

Run:

```bash
timeout 60s bash scripts/verify_phase0_spec_consistency.sh
```

Expected:
- PASS
- 所有文档都使用同一套 v1 运行拓扑表述

- [ ] **Step 5: 提交这一组变更**

```bash
git add scripts/verify_phase0_spec_consistency.sh \
  docs/00-总设计/总体项目设计.md \
  docs/03-系统架构/架构设计.md \
  docs/07-部署运维/部署手册.md \
  docs/04-功能设计/M002-平台任务执行与调度中心功能设计.md \
  docs/04-功能设计/M203-安全公告调度运行与结果功能设计.md

git commit -m "docs: unify v1 runtime topology wording" \
  -m "What: align overall design, architecture, deployment, and task/monitoring module docs around one canonical v1 runtime topology.
Why: the repository previously mixed 'single-process' and 'separate worker/scheduler service' narratives, which would make implementation DoD ambiguous.
Validation: timeout 60s bash scripts/verify_phase0_spec_consistency.sh"
```

### Task 3: 修正实现顺序，明确首个垂直切片优先级

**Files:**
- Modify: `docs/04-功能设计/M901-功能模块关系与开发顺序设计.md`
- Modify: `docs/04-功能设计/README.md`
- Modify: `docs/04-功能设计/M201-安全公告手动提取功能设计.md`
- Modify: `docs/04-功能设计/M101-CVE检索工作台功能设计.md`
- Test: 继续复用 `scripts/verify_phase0_spec_consistency.sh`，新增顺序断言

- [ ] **Step 1: 先把顺序校验补进一致性脚本，确认当前规范失败**

Extend `scripts/verify_phase0_spec_consistency.sh` with:

```bash
rg -q "平台.*公告手动提取.*CVE.*监控.*投递" \
  docs/04-功能设计/M901-功能模块关系与开发顺序设计.md
rg -q "公告手动提取.*正文模式.*(首个可运行垂直切片|首个切片)" \
  docs/04-功能设计/M201-安全公告手动提取功能设计.md
rg -q "CVE.*首个公告切片稳定后接入|首个公告切片稳定后.*CVE" \
  docs/04-功能设计/M101-CVE检索工作台功能设计.md
rg -q "实现阶段顺序|实现顺序" docs/04-功能设计/README.md

if rg -q "先完成 CVE 场景，再扩公告场景实现" \
  docs/04-功能设计/M901-功能模块关系与开发顺序设计.md; then
  echo "found obsolete implementation order in M901" >&2
  exit 1
fi

if rg -q "先完成 CVE 场景，再扩公告场景实现" docs/04-功能设计/README.md; then
  echo "found obsolete implementation order in feature README" >&2
  exit 1
fi

if rg -q "URL.*正文.*同等优先" docs/04-功能设计/M201-安全公告手动提取功能设计.md; then
  echo "found obsolete slice-priority wording in M201" >&2
  exit 1
fi
```

- [ ] **Step 2: 运行脚本，确认当前顺序定义确实冲突**

Run:

```bash
timeout 60s bash scripts/verify_phase0_spec_consistency.sh
```

Expected:
- FAIL
- 报错说明 `M901` 仍然保留 “先 CVE 后公告” 的旧顺序

- [ ] **Step 3: 修改执行顺序相关文档**

Make the implementation order explicit and consistent:

```text
实现阶段顺序：
1. 平台最小底座
2. 安全公告手动提取正文模式闭环
3. 安全公告 URL 模式
4. CVE fast-first / graph-ready
5. 监控、投递、完整观测
```

Update:
- `M901`：删除“先完成 CVE 场景，再扩公告场景实现”
- `功能设计/README.md`：补一段“实现阶段顺序”说明，避免只剩文档编写顺序
- `M201`：明确正文模式是首个可运行垂直切片
- `M101`：补一句“CVE 实现在首个公告切片稳定后接入”

- [ ] **Step 4: 重新运行一致性脚本，确认顺序统一**

Run:

```bash
timeout 60s bash scripts/verify_phase0_spec_consistency.sh
```

Expected:
- PASS
- `M901`、`README`、`M201`、`M101` 对首个切片与后续顺序描述一致

- [ ] **Step 5: 提交这一组变更**

```bash
git add docs/04-功能设计/M901-功能模块关系与开发顺序设计.md \
  docs/04-功能设计/README.md \
  docs/04-功能设计/M201-安全公告手动提取功能设计.md \
  docs/04-功能设计/M101-CVE检索工作台功能设计.md \
  scripts/verify_phase0_spec_consistency.sh

git commit -m "docs: prioritize announcement manual extraction as the first slice" \
  -m "What: update implementation-order docs so the first runnable vertical slice is announcement manual extraction, followed by CVE and monitoring/delivery expansions.
Why: this ordering validates the platform runtime with lower external dependency risk than the CVE flow.
Validation: timeout 60s bash scripts/verify_phase0_spec_consistency.sh"
```

### Task 4: 做 Phase 0 的最终证据化验证

**Files:**
- Test only: `scripts/verify_sql_init_order.sh`
- Test only: `scripts/verify_phase0_spec_consistency.sh`

- [ ] **Step 1: 重新初始化临时 PostgreSQL 并完整验证 SQL 顺序**

Run:

```bash
docker rm -f aetherflow-phase0-pg || true
docker run --rm -d --name aetherflow-phase0-pg \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=aetherflow_phase0 \
  -p 55432:5432 postgres:16-alpine

until docker exec aetherflow-phase0-pg pg_isready -U postgres >/dev/null 2>&1; do
  sleep 1
done

export DATABASE_URL=postgresql://postgres:postgres@127.0.0.1:55432/aetherflow_phase0
timeout 60s bash scripts/verify_sql_init_order.sh
```

Expected:
- PASS

- [ ] **Step 2: 运行规范一致性检查**

Run:

```bash
timeout 60s bash scripts/verify_phase0_spec_consistency.sh
```

Expected:
- PASS

- [ ] **Step 3: 检查工作区只包含本阶段预期变更**

Run:

```bash
git status --short
git diff --check
git diff --stat -- scripts docs/00-总设计 docs/03-系统架构 docs/04-功能设计 docs/05-数据库 docs/07-部署运维
```

Expected:
- 没有 whitespace error
- 只包含本阶段定义的 SQL / 文档 / 验证脚本改动

- [ ] **Step 4: 清理临时 PostgreSQL，避免 Phase 1 撞端口**

Run:

```bash
docker rm -f aetherflow-phase0-pg || true
```

Expected:
- PASS
- 55432 端口被释放，Phase 1 不会因为残留 PostgreSQL 容器撞端口

- [ ] **Step 5: 记录 Phase 0 完成结论**

Completion criteria:
- SQL 可以按文档顺序在干净 PostgreSQL 上执行成功
- 平台域不再反向硬依赖公告域
- v1 运行拓扑表述不再互相冲突
- `M901` 与模块 README 已明确“公告手动提取优先于 CVE 实现”
