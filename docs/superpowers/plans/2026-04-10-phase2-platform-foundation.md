# Phase 2 Platform Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在不提前进入真实场景业务链的前提下，把 Phase 2 平台最小底座推进到可运行状态，完成 `claim / attempt / artifact / health / scheduler heartbeat` 的真实 PostgreSQL 闭环。

**Architecture:** Phase 2 不开放依赖 `scene_run_id` 的公共任务接口，只落平台内部运行时能力。Worker 通过 PostgreSQL claim `task_jobs` 并创建 `task_attempts`，Artifact 通过文件系统 + 元数据表落地，attempt 与 Artifact 的归属用 `task_attempt_artifacts` 关联表表达。Health summary 通过 `runtime_heartbeats` 聚合 Database / Worker / Scheduler 的最小健康状态，Scheduler 只写 heartbeat，不创建监控任务。

**Tech Stack:** Python 3.11、FastAPI、SQLAlchemy 2.x、Alembic、pytest、PostgreSQL 16、argparse、本地文件系统

---

## 执行回写（2026-04-13）

- Phase 2 已按本计划完成首轮实现，运行闭环覆盖 `claim / attempt / artifact / health / scheduler heartbeat`。
- 后续根据代码审查补做了四类实现修复：
  - `artifact_root` 固定解析为稳定绝对路径，消除 runtime cwd 漂移。
  - `Engine / sessionmaker` 按 `database_url` 缓存复用，避免重复创建连接池。
  - Artifact 数据库持久化失败时回删已写文件与空目录。
  - Worker 补偿链改为先落失败状态，再 best-effort 清理 Artifact；清理异常不覆盖原始异常。
- 当前最终验证基线：
  - `TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev timeout 60s ./.venv/bin/python -m pytest backend/tests -q`
  - 结果：`30 passed in 13.15s`
- 验证注意事项：
  - 本计划中的 PostgreSQL 测试若共享同一个 `TEST_DATABASE_URL`，不得并行执行多个会 `DROP/CREATE public schema` 的 pytest 命令，否则会互相踩库。

---

## 文件映射

- `backend/alembic/versions/20260410_0002_phase2_platform_foundation.py`
  - Phase 2 新增表与约束迁移
- `backend/app/models/platform.py`
  - 补充 `TaskAttemptArtifact`、`RuntimeHeartbeat` ORM 模型
- `backend/app/config.py`
  - Phase 2 运行时配置项：数据库、Artifact 根目录、heartbeat 参数
- `backend/app/platform/__init__.py`
  - 平台运行时服务包入口
- `backend/app/platform/task_runtime.py`
  - claim、attempt 状态流转和最小任务执行服务
- `backend/app/platform/artifact_store.py`
  - Artifact 本地落盘、checksum、读取能力
- `backend/app/platform/runtime_heartbeats.py`
  - heartbeat upsert 与读取
- `backend/app/platform/health_summary.py`
  - `/health/summary` 聚合逻辑
- `backend/app/api/v1/platform/artifacts.py`
  - Artifact 元数据与内容读取接口
- `backend/app/api/v1/platform/health.py`
  - 基础健康检查与详细摘要接口
- `backend/app/api/router.py`
  - 注册新增平台 API
- `backend/app/worker/runtime.py`
  - Worker 的 `--once` 与循环执行逻辑
- `backend/app/worker/main.py`
  - 接线 Worker runtime
- `backend/app/scheduler/runtime.py`
  - Scheduler heartbeat runtime
- `backend/app/scheduler/main.py`
  - 接线 Scheduler runtime
- `backend/tests/test_phase2_schema_contract.py`
  - Phase 2 schema 契约测试
- `backend/tests/test_task_runtime.py`
  - claim / attempt / 状态流转测试
- `backend/tests/test_artifact_store.py`
  - Artifact 落盘与关联测试
- `backend/tests/test_artifact_api.py`
  - Artifact API 测试
- `backend/tests/test_health_summary.py`
  - heartbeat / health summary 判级测试
- `backend/tests/test_phase2_runtime_loop.py`
  - 最小端到端闭环测试

---

### Task 0: 准备隔离执行工作区与基线环境

**Files:**
- Test only: 当前仓库 Git 状态
- Test only: worktree 环境和基线测试结果

- [ ] **Step 1: 确认执行 worktree 是干净基线**

Run:

```bash
git status --short --branch
git diff --stat
pwd
```

Expected:
- 当前目录位于隔离 worktree
- 工作树干净

- [ ] **Step 2: 为当前 worktree 准备后端环境**

Run:

```bash
timeout 60s bash scripts/bootstrap_backend_env.sh
```

Expected:
- PASS
- 当前 worktree 下生成 `.venv`

- [ ] **Step 3: 启动开发 PostgreSQL 并确认可用**

Run:

```bash
timeout 60s make pg-up
```

Expected:
- PASS
- `127.0.0.1:55432` 上的 PostgreSQL 可连接

- [ ] **Step 4: 跑一组 Phase 1 基线测试，确认起点可用**

Run:

```bash
TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev \
timeout 60s ./.venv/bin/python -m pytest \
  backend/tests/test_app_boot.py \
  backend/tests/test_runtime_entrypoints.py \
  backend/tests/test_migrations.py -q
```

Expected:
- PASS
- 证明工作区起点仍是 Phase 1 干净基线

### Task 1: 补齐 Phase 2 schema 与配置契约

**Files:**
- Create: `backend/alembic/versions/20260410_0002_phase2_platform_foundation.py`
- Create: `backend/tests/test_phase2_schema_contract.py`
- Modify: `backend/app/models/platform.py`
- Modify: `backend/app/models/__init__.py`
- Modify: `backend/app/config.py`
- Modify: `backend/tests/test_migrations.py`

- [ ] **Step 1: 先写会失败的 schema 契约测试**

Create `backend/tests/test_phase2_schema_contract.py` with assertions for:

```python
from app.db.base import Base


def test_phase2_metadata_contains_runtime_tables() -> None:
    assert "task_attempt_artifacts" in Base.metadata.tables
    assert "runtime_heartbeats" in Base.metadata.tables


def test_artifact_table_remains_content_neutral() -> None:
    artifacts = Base.metadata.tables["artifacts"]
    assert "producer_attempt_id" not in artifacts.c


def test_runtime_heartbeats_has_unique_role_instance() -> None:
    runtime_heartbeats = Base.metadata.tables["runtime_heartbeats"]
    constraint_names = {constraint.name for constraint in runtime_heartbeats.constraints}
    assert "uq_runtime_heartbeats_role_instance_name" in constraint_names
```

- [ ] **Step 2: 运行 schema 测试，确认它先失败**

Run:

```bash
TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev \
timeout 60s ./.venv/bin/python -m pytest \
  backend/tests/test_migrations.py \
  backend/tests/test_phase2_schema_contract.py -q
```

Expected:
- FAIL
- 失败原因是模型或迁移尚未包含 `task_attempt_artifacts` / `runtime_heartbeats`

- [ ] **Step 3: 写出最小 schema 与配置实现**

Implement:

```python
# backend/app/config.py
@dataclass(frozen=True)
class Settings:
    app_name: str = "AetherFlow API"
    database_url: str = ""
    artifact_root: str = "./backend/.runtime/artifacts"
    runtime_heartbeat_interval_seconds: int = 10
    runtime_heartbeat_stale_seconds: int = 30
```

Add ORM models for:

- `TaskAttemptArtifact`
- `RuntimeHeartbeat`

Migration responsibilities:

- create `task_attempt_artifacts`
- create `runtime_heartbeats`
- add uniqueness on `(role, instance_name)`
- do **not** add `producer_attempt_id` to `artifacts`

- [ ] **Step 4: 重新运行 schema 测试**

Run:

```bash
TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev \
timeout 60s ./.venv/bin/python -m pytest \
  backend/tests/test_migrations.py \
  backend/tests/test_phase2_schema_contract.py -q
```

Expected:
- PASS

- [ ] **Step 5: 提交这一组变更**

```bash
git add backend/alembic/versions/20260410_0002_phase2_platform_foundation.py \
  backend/app/models/platform.py \
  backend/app/models/__init__.py \
  backend/app/config.py \
  backend/tests/test_migrations.py \
  backend/tests/test_phase2_schema_contract.py

git commit -m "构建: 补齐 Phase 2 平台底座 schema 契约" \
  -m "修改了什么：新增 task_attempt_artifacts 与 runtime_heartbeats 迁移和 ORM 模型，并补充 Phase 2 运行时配置项。
为什么这么改：Phase 2 需要在不污染 artifacts 主表语义的前提下表达 attempt 输出关系，并为 health summary 提供跨进程 heartbeat 数据来源。
验证了什么：TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev timeout 60s ./.venv/bin/python -m pytest backend/tests/test_migrations.py backend/tests/test_phase2_schema_contract.py -q"
```

### Task 2: 先做 task claim 与状态流转，再接 Worker runtime

**Files:**
- Create: `backend/app/platform/__init__.py`
- Create: `backend/app/platform/task_runtime.py`
- Create: `backend/app/worker/runtime.py`
- Create: `backend/tests/test_task_runtime.py`
- Modify: `backend/app/worker/main.py`

- [ ] **Step 1: 先写会失败的 task runtime 测试**

Create `backend/tests/test_task_runtime.py` with fixture-seeded `task_jobs` samples:

```python
def test_claim_next_job_creates_running_attempt(...):
    job_id = seed_job(status="queued", scene_name="announcement")

    claimed = claim_next_job(...)

    assert claimed.job_id == job_id
    assert claimed.attempt_no == 1
    assert load_job(job_id).status == "running"


def test_mark_attempt_failed_updates_job_error(...):
    ...


def test_mark_attempt_succeeded_sets_finished_at(...):
    ...
```

- [ ] **Step 2: 运行 task runtime 测试，确认先失败**

Run:

```bash
TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev \
timeout 60s ./.venv/bin/python -m pytest backend/tests/test_task_runtime.py -q
```

Expected:
- FAIL
- 失败原因是 `task_runtime` 服务尚不存在

- [ ] **Step 3: 写最小 claim / attempt / Worker once 实现**

Implement:

- `claim_next_job(...)` with `SELECT ... FOR UPDATE SKIP LOCKED`
- `mark_attempt_failed(...)`
- `mark_attempt_succeeded(...)`
- Worker `--once` calls runtime service once and exits `0`

Rules:

- Phase 2 测试可以 seed 合成 `task_jobs` 行
- 不新增 `/platform/tasks*` HTTP 接口
- 不实现 retry API

- [ ] **Step 4: 重新运行 task runtime 测试**

Run:

```bash
TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev \
timeout 60s ./.venv/bin/python -m pytest backend/tests/test_task_runtime.py -q
```

Expected:
- PASS

- [ ] **Step 5: 提交这一组变更**

```bash
git add backend/app/platform/__init__.py \
  backend/app/platform/task_runtime.py \
  backend/app/worker/runtime.py \
  backend/app/worker/main.py \
  backend/tests/test_task_runtime.py

git commit -m "构建: 落地 Phase 2 任务 claim 与 attempt 流转" \
  -m "修改了什么：新增 PostgreSQL claim、attempt 状态流转服务，并把 Worker --once 接到最小 runtime。
为什么这么改：Phase 2 需要证明 task_jobs 到 task_attempts 的真实运行闭环，而不是停留在 CLI 壳。
验证了什么：TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev timeout 60s ./.venv/bin/python -m pytest backend/tests/test_task_runtime.py -q"
```

### Task 3: 落 Artifact 最小存储、读取与 attempt 关联

**Files:**
- Create: `backend/app/platform/artifact_store.py`
- Create: `backend/app/api/v1/platform/artifacts.py`
- Create: `backend/tests/test_artifact_store.py`
- Create: `backend/tests/test_artifact_api.py`
- Modify: `backend/app/api/router.py`
- Modify: `backend/app/worker/runtime.py`

- [ ] **Step 1: 先写会失败的 Artifact 测试**

Create `backend/tests/test_artifact_store.py`:

```python
def test_write_text_artifact_creates_file_and_metadata(...):
    artifact = write_text_artifact(...)
    assert artifact.artifact_kind == "text"
    assert artifact.checksum
    assert read_back_file(artifact.storage_path) == "hello"


def test_attempt_artifact_relation_is_persisted(...):
    ...
```

Create `backend/tests/test_artifact_api.py`:

```python
def test_get_artifact_metadata_hides_storage_path(...):
    ...


def test_get_artifact_content_returns_text_body(...):
    ...
```

- [ ] **Step 2: 运行 Artifact 测试，确认先失败**

Run:

```bash
TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev \
timeout 60s ./.venv/bin/python -m pytest \
  backend/tests/test_artifact_store.py \
  backend/tests/test_artifact_api.py -q
```

Expected:
- FAIL
- 失败原因是 Artifact store 和 API 尚不存在

- [ ] **Step 3: 写最小 Artifact 实现**

Implement:

- file-system backed `write_text_artifact(...)`
- metadata persistence into `artifacts`
- relation persistence into `task_attempt_artifacts`
- `GET /api/v1/platform/artifacts/{artifact_id}`
- `GET /api/v1/platform/artifacts/{artifact_id}/content`

Rules:

- API 不暴露底层 `storage_path`
- 文本内容直接返回
- 二进制内容保留下载流接口形态，但不扩对象存储

- [ ] **Step 4: 重新运行 Artifact 测试**

Run:

```bash
TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev \
timeout 60s ./.venv/bin/python -m pytest \
  backend/tests/test_artifact_store.py \
  backend/tests/test_artifact_api.py -q
```

Expected:
- PASS

- [ ] **Step 5: 提交这一组变更**

```bash
git add backend/app/platform/artifact_store.py \
  backend/app/api/v1/platform/artifacts.py \
  backend/app/api/router.py \
  backend/app/worker/runtime.py \
  backend/tests/test_artifact_store.py \
  backend/tests/test_artifact_api.py

git commit -m "构建: 落地 Phase 2 Artifact 最小基座" \
  -m "修改了什么：新增 Artifact 本地存储、metadata/content API，以及 attempt 与 Artifact 的关联落库逻辑。
为什么这么改：Phase 2 必须证明 Worker 的最小执行结果可以沉淀为可读取的 canonical content，而不是只更新任务状态。
验证了什么：TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev timeout 60s ./.venv/bin/python -m pytest backend/tests/test_artifact_store.py backend/tests/test_artifact_api.py -q"
```

### Task 4: 实现 heartbeat 与 health summary，保持 Scheduler 只做 heartbeat

**Files:**
- Create: `backend/app/platform/runtime_heartbeats.py`
- Create: `backend/app/platform/health_summary.py`
- Create: `backend/app/scheduler/runtime.py`
- Create: `backend/tests/test_health_summary.py`
- Modify: `backend/app/api/v1/platform/health.py`
- Modify: `backend/app/scheduler/main.py`
- Modify: `backend/app/worker/runtime.py`

- [ ] **Step 1: 先写会失败的 health summary 测试**

Create `backend/tests/test_health_summary.py`:

```python
def test_health_summary_reports_database_healthy(...):
    ...


def test_worker_heartbeat_becomes_degraded_after_stale_threshold(...):
    ...


def test_scheduler_missing_heartbeat_reports_down(...):
    ...
```

- [ ] **Step 2: 运行 health summary 测试，确认先失败**

Run:

```bash
TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev \
timeout 60s ./.venv/bin/python -m pytest backend/tests/test_health_summary.py -q
```

Expected:
- FAIL
- 失败原因是 `runtime_heartbeats` 服务和 `/health/summary` 还不存在

- [ ] **Step 3: 写 heartbeat 与 health summary 实现**

Implement:

- heartbeat upsert for worker / scheduler
- summary contract with only `api/database/worker/scheduler/notes`
- fixed TTL rule from spec
- scheduler `--once` only writes heartbeat and exits `0`

Rules:

- 不返回 `enabled_sources`
- 不返回 `enabled_channels`
- 不创建监控任务

- [ ] **Step 4: 重新运行 health summary 测试**

Run:

```bash
TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev \
timeout 60s ./.venv/bin/python -m pytest backend/tests/test_health_summary.py -q
```

Expected:
- PASS

- [ ] **Step 5: 提交这一组变更**

```bash
git add backend/app/platform/runtime_heartbeats.py \
  backend/app/platform/health_summary.py \
  backend/app/scheduler/runtime.py \
  backend/app/api/v1/platform/health.py \
  backend/app/scheduler/main.py \
  backend/app/worker/runtime.py \
  backend/tests/test_health_summary.py

git commit -m "构建: 落地 Phase 2 健康摘要与心跳判级" \
  -m "修改了什么：新增 runtime_heartbeats、health summary 聚合、Worker/Scheduler 心跳写入，并把 Scheduler 保持在 heartbeat 边界内。
为什么这么改：Phase 2 需要最小跨进程健康视图，但不能把系统页提前扩成监控平台。
验证了什么：TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev timeout 60s ./.venv/bin/python -m pytest backend/tests/test_health_summary.py -q"
```

### Task 5: 端到端验证最小平台闭环并补证据链

**Files:**
- Create: `backend/tests/test_phase2_runtime_loop.py`
- Modify: `docs/09-AI开发日志/日志/YYYY-MM-DD_SessionNNN_*.md`

- [ ] **Step 1: 先写一个会失败的端到端闭环测试**

Create `backend/tests/test_phase2_runtime_loop.py`:

```python
def test_worker_once_processes_seeded_job_and_creates_artifact(...):
    job_id = seed_job(status="queued", scene_name="announcement")

    result = run_worker_once(...)

    assert result.returncode == 0
    assert load_job(job_id).status == "succeeded"
    assert load_attempts(job_id)[0].status == "succeeded"
    assert load_attempt_artifacts(job_id)


def test_scheduler_once_updates_heartbeat_and_summary(...):
    ...
```

- [ ] **Step 2: 运行端到端测试，确认还存在收尾缺口**

Run:

```bash
TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev \
timeout 60s ./.venv/bin/python -m pytest backend/tests/test_phase2_runtime_loop.py -q
```

Expected:
- FAIL
- 失败原因是还有 glue code 或命令行接线未补齐

- [ ] **Step 3: 补齐最小 glue code，不扩范围**

Rules:

- 只修端到端闭环缺口
- 不引入 `/platform/tasks*`
- 不引入真实场景 run 写路径
- 不扩 `health/summary` 字段

- [ ] **Step 4: 跑全量 Phase 2 证据链**

Run:

```bash
TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev \
timeout 60s ./.venv/bin/python -m pytest backend/tests -q
```

Expected:
- PASS
- 证明 Phase 1 测试不回归，Phase 2 新测试全部通过

- [ ] **Step 5: 提交收尾与证据记录**

```bash
git add backend/tests/test_phase2_runtime_loop.py docs/09-AI开发日志/日志/*.md

git commit -m "验证: 补齐 Phase 2 平台底座证据链" \
  -m "修改了什么：新增 Phase 2 最小端到端闭环测试，并记录本轮实现与验证证据。
为什么这么改：Phase 2 的完成标准不是口头声明，而是可重复的真实 PostgreSQL 运行证据。
验证了什么：TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev timeout 60s ./.venv/bin/python -m pytest backend/tests -q"
```
