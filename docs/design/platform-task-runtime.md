# 平台任务运行时实现设计

> 本文描述 AetherFlow 平台任务底座：TaskJob、TaskAttempt、Worker、Scheduler、
> heartbeat、任务查询和失败重排。

## 1. 模块定位

本模块属于 `Platform Runtime` 边界。

它解决的问题：

- 用统一任务表承载 CVE 和公告场景。
- 用 attempt 记录每次 Worker 执行。
- 用 `SELECT ... FOR UPDATE SKIP LOCKED` 保证并发领取任务时不重复执行。
- 用 heartbeat 记录 Worker / Scheduler 活性。
- 向前端任务中心暴露任务列表、详情和失败重试。

它不解决的问题：

- 不定义 CVE 或公告业务结果结构。
- 不做复杂调度队列。
- 不负责分布式消息中间件。
- 不自动为场景创建新的 run；重试只重排同一个 job。

## 2. 数据模型

`TaskJob` 表：

- 表名：`task_jobs`
- 主键：`job_id`
- 字段：
  - `scene_name`
  - `job_type`
  - `trigger_kind`
  - `status`
  - `payload_json`
  - `scheduled_at`
  - `started_at`
  - `finished_at`
  - `last_error`
  - `created_at`
  - `updated_at`
- 约束：
  - `scene_name IN ('cve', 'announcement')`
- 索引：
  - `scene_name, status`
  - `created_at`
  - `trigger_kind`

`TaskAttempt` 表：

- 表名：`task_attempts`
- 主键：`attempt_id`
- 外键：`job_id -> task_jobs.job_id`
- 字段：
  - `attempt_no`
  - `status`
  - `worker_name`
  - `error_message`
  - `started_at`
  - `finished_at`
- 唯一约束：
  - `(job_id, attempt_no)`

`RuntimeHeartbeat` 表：

- 表名：`runtime_heartbeats`
- 主键：
  - `role`
  - `instance_name`
- 字段：
  - `heartbeat_at`
  - `created_at`
  - `updated_at`

## 3. 代码入口

任务 claim 和 attempt 收口：

- `backend/app/platform/task_runtime.py::claim_next_job`
- `backend/app/platform/task_runtime.py::finish_attempt_success`
- `backend/app/platform/task_runtime.py::finish_attempt_failure`
- `backend/app/platform/task_runtime.py::mark_attempt_succeeded`
- `backend/app/platform/task_runtime.py::mark_attempt_failed`

Worker：

- `backend/app/worker/runtime.py::process_once`
- `backend/app/worker/runtime.py::run_worker_once`
- `backend/app/worker/runtime.py::build_worker_name`

Scheduler：

- `backend/app/scheduler/runtime.py::run_scheduler_once`

Heartbeat：

- `backend/app/platform/runtime_heartbeats.py::build_instance_name`
- `backend/app/platform/runtime_heartbeats.py::upsert_runtime_heartbeat`
- `backend/app/platform/runtime_heartbeats.py::get_latest_heartbeat_at`

任务查询 API：

- `backend/app/platform/tasks.py::list_platform_tasks`
- `backend/app/platform/tasks.py::get_platform_task_detail`
- `backend/app/platform/tasks.py::requeue_failed_task`
- `backend/app/api/v1/platform/tasks.py`

## 4. Claim 契约

Session 模式入口：

```text
claim_next_job(session, scene_name=..., worker_name=...)
```

规则：

- `scene_name` 必填。
- 只领取 `TaskJob.status == "queued"`。
- 按 `created_at, job_id` 排序。
- 使用 `with_for_update(skip_locked=True)`。
- 领取后：
  - `job.status = "running"`
  - `job.started_at = job.started_at or now`
  - `job.finished_at = None`
  - `job.last_error = None`
  - `job.updated_at = now`
  - 新建 `TaskAttempt(status="running")`
  - `attempt_no = max(existing attempt_no) + 1`

Factory 模式入口：

```text
claim_next_job(session_factory, worker_name=...)
```

规则：

- 不按 scene 过滤。
- 返回轻量 `ClaimedTaskAttempt` dataclass。
- 用于早期最小 worker once artifact 流程。

## 5. Worker 分派契约

`process_once` 使用 Session 模式。

领取顺序：

```text
claim scene_name="cve"
  -> 如果没有，claim scene_name="announcement"
  -> 如果仍没有，return False
```

支持的任务：

- `cve / cve_patch_agent_graph`
  - 查询绑定的 `CVERun.run_id`
  - 调用 `execute_cve_run(session, run_id=run_id)`
  - 根据 `CVERun.status` 收口 attempt
- `announcement / announcement_manual_extract`
  - 查询绑定的 `AnnouncementRun.run_id`
  - 调用 `execute_announcement_run`
  - 根据 run status 收口 attempt
- `announcement / announcement_monitor_fetch`
  - 调用 `execute_monitor_fetch`
  - 直接标记 attempt success

不支持的任务类型：

- `finish_attempt_failure`
- error message：`不支持的任务类型: {scene_name}/{job_type}`

异常处理：

- 捕获任意异常。
- `finish_attempt_failure(session, attempt=attempt, error_message=str(exc))`
- `session.commit()`
- 返回 `True`，表示本轮确实处理了一个任务。

## 6. Attempt 收口

成功：

```text
finish_attempt_success(session, attempt)
  -> attempt.status = "succeeded"
  -> attempt.finished_at = now
  -> attempt.error_message = None
  -> job.status = "succeeded"
  -> job.finished_at = now
  -> job.updated_at = now
  -> job.last_error = None
```

失败：

```text
finish_attempt_failure(session, attempt, error_message)
  -> attempt.status = "failed"
  -> attempt.finished_at = now
  -> attempt.error_message = error_message
  -> job.status = "failed"
  -> job.finished_at = now
  -> job.updated_at = now
  -> job.last_error = error_message
```

CVE 特殊收口：

- `CVERun.status == "succeeded"` -> attempt success。
- `CVERun.status == "failed"` -> attempt failure。
- 其它状态 -> `RuntimeError("CVE run 未收口: ...")`。

## 7. Scheduler 契约

入口：

- `run_scheduler_once(settings, instance_name=None)`

规则：

- `settings.database_url` 为空时抛错。
- 写入 role=`scheduler` 的 heartbeat。
- 调用 `process_scheduled_delivery_records(session_factory)`。

当前 Scheduler 是最小职责：

- heartbeat。
- 到期投递处理。
- 不负责扫描公告源。
- 不负责 CVE run 调度。

## 8. Heartbeat 契约

实例名：

```text
build_instance_name(role, explicit_name=None)
  -> explicit_name or "{role}@{hostname}:{pid}"
```

upsert：

```text
upsert_runtime_heartbeat(session_factory, role, instance_name, heartbeat_at=None)
```

规则：

- 如果 `(role, instance_name)` 不存在，插入。
- 如果存在，更新 `heartbeat_at` 和 `updated_at`。
- 默认 heartbeat time 为当前 UTC 时间。

读取最新 heartbeat：

```text
get_latest_heartbeat_at(session_factory, role)
  -> 按 heartbeat_at desc 取第一条
```

## 9. 任务查询与重排

列表：

- API：`GET /api/v1/platform/tasks`
- 参数：
  - `scene_name`
  - `status`
  - `trigger_kind`
  - `page`
  - `page_size`
- 返回：
  - `items`
  - `total`
  - `page`
  - `page_size`

详情：

- API：`GET /api/v1/platform/tasks/{job_id}`
- 返回 job 基本信息、scene run id、payload summary、last error 和 attempts。

重排：

- API：`POST /api/v1/platform/tasks/{job_id}/retry`
- 只允许 `job.status == "failed"`。
- 行为：
  - `status = "queued"`
  - `started_at = None`
  - `finished_at = None`
  - `last_error = None`
  - `updated_at = now`
- 不创建新的场景 run。

## 10. 错误与降级

缺数据库配置：

- Worker once 和 Scheduler once 都抛 `RuntimeError`。

基于 Session claim 未传 scene：

- 抛 `ValueError("基于 Session claim task 时必须提供 scene_name")`。

任务不存在：

- 任务详情 API 返回 404。
- retry API 返回 404。

非 failed 任务 retry：

- `requeue_failed_task` 抛 `ValueError`。
- API 返回 400。

Worker 执行异常：

- attempt 和 job 都标记 failed。
- 错误写入 `TaskAttempt.error_message` 和 `TaskJob.last_error`。

## 11. 测试映射

任务运行时：

- `backend/tests/test_task_runtime.py`
- `backend/tests/test_platform_task_runtime.py`

Worker：

- `backend/tests/test_worker_cve_flow.py`
- `backend/tests/test_runtime_entrypoints.py`

Scheduler / heartbeat：

- `backend/tests/test_health_summary.py`
- `backend/tests/test_phase2_runtime_loop.py`

任务 API：

- `backend/tests/test_platform_overview_api.py`
- `frontend/src/test/platform-pages.test.tsx`

建议验证命令：

```bash
timeout 60s ./.venv/bin/python -m pytest backend/tests/test_task_runtime.py backend/tests/test_platform_task_runtime.py backend/tests/test_worker_cve_flow.py backend/tests/test_health_summary.py -q
```

## 12. 源码复刻清单

如果源码丢失，按以下顺序复刻：

1. 先定义 `TaskJob`、`TaskAttempt`、`RuntimeHeartbeat` 模型和约束。
2. 实现 `_next_attempt_no`。
3. 实现 Session 模式 `claim_next_job`，必须使用 `skip_locked`。
4. 实现 Factory 模式 `claim_next_job`，返回 `ClaimedTaskAttempt`。
5. 实现 success / failure 收口函数。
6. 实现 Worker 的 scene/job_type 分派。
7. 实现 CVE run 状态到 attempt 状态的映射。
8. 实现 Scheduler heartbeat 和投递处理。
9. 实现平台任务列表、详情和 retry API。
10. 补齐 Worker、task runtime、heartbeat、API 测试。

## 13. 已知差距

当前 Worker 同时存在 `process_once` 场景运行链路和 `run_worker_once` 早期 artifact
最小链路。长期应明确 `run_worker_once` 是否仅保留为兼容测试入口，避免后续误把
artifact demo 流程当成主 Worker 行为。
