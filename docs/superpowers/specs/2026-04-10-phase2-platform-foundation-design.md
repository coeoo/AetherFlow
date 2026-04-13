# Phase 2 Platform Foundation Design

> **范围说明**：本文只定义 Phase 2「平台最小底座」的实现边界，不把 CVE 主链、公告 URL 模式、监控扫描器和完整投递提前拉进来。

---

## 🎯 目标

Phase 2 的目标是把当前仓库从「Phase 1 工程骨架」推进到「最小平台底座可运行」。

本阶段只证明四件事：

1. `task_jobs / task_attempts` 的 claim 与状态流转可以在真实 PostgreSQL 中工作。
2. Worker 能把一次最小执行结果落成 Artifact，并通过 API 读取。
3. API 能聚合 Database / Worker / Scheduler 的最小健康摘要。
4. Scheduler 在本阶段只承担 heartbeat，不承担监控扫描与批次创建。

---

## 🚫 非目标

Phase 2 明确不做以下内容：

- 不进入 CVE 业务主链
- 不进入安全公告 URL 抓取链
- 不提前落 `announcement_runs / announcement_documents / announcement_intelligence_packages` 的真实写路径
- 不开放依赖 `scene_run_id` 的任务中心查询/重试接口
- 不把 Scheduler 扩成真正的监控扫描器
- 不把 `enabled_sources / enabled_channels` 拉进健康摘要
- 不把 `producer_attempt_id` 一类字段塞进 `artifacts` 主表

---

## 🔒 核心决策

### 决策 1：Phase 2 不开放对外任务中心接口

当前平台契约明确要求：

- 一个 `task_job` 只绑定一次场景执行
- 一个 `task_job` 只对应一个真实场景 `run`
- 任务详情如果对外开放，必须能稳定回查 `scene_run_id`

因此，Phase 2 不开放以下接口：

- `GET /api/v1/platform/tasks`
- `GET /api/v1/platform/tasks/{job_id}`
- `POST /api/v1/platform/tasks/{job_id}/retry`

这些接口延期到 3A 及之后，等首个真实场景写路径落地，再建立 `task_job -> scene_run` 的产品级对外查询语义。

### 决策 2：Phase 2 允许测试夹具预置 `task_jobs`，但不形成产品级“内部 helper”

Phase 2 仍需验证 claim / attempt / artifact / health 的真实闭环。

为了不提前引入最小场景 run 写路径，本阶段允许在自动化测试中直接向真实 PostgreSQL 预置 `task_jobs` 样本，用于驱动 Worker runtime。

这条规则只适用于测试夹具：

- 它不是对外接口
- 它不是产品级内部 helper
- 它不改变 `task_job` 在产品语义上应绑定真实场景 `run` 的约束

### 决策 3：`artifacts` 保持中立，attempt 归属通过关联表表达

`artifacts` 是跨场景共享的 canonical content store，只描述内容对象本身：

- 它可以被 CVE、公告、抓取审计等多方引用
- 它不应该直接承载某次 runtime 执行的归属字段

因此，Phase 2 不在 `artifacts` 上增加 `producer_attempt_id`。

改为新增平台技术关联表 `task_attempt_artifacts`：

- `attempt_id`
- `artifact_id`
- `created_at`

这样既能表达“某次 attempt 产出了什么”，又不污染 Artifact 的共享内容模型。

### 决策 4：健康摘要在 Phase 2 收口为最小字段集

Phase 2 的 `GET /api/v1/platform/health/summary` 固定返回：

- `api`
- `database`
- `worker`
- `scheduler`
- `notes`

明确延期字段：

- `enabled_sources`
- `enabled_channels`

它们属于监控源与投递中心真正落地后的配置摘要，不进入本阶段的 health contract。

### 决策 5：Heartbeat 规则必须是 fixed contract

新增平台技术表 `runtime_heartbeats`，用于跨进程共享 Worker / Scheduler 的最小存活状态。

固定契约如下：

- `role`: `worker` / `scheduler`
- `instance_name`: 默认 `<role>@<hostname>:<pid>`
- 刷新间隔配置项：`AETHERFLOW_RUNTIME_HEARTBEAT_INTERVAL_SECONDS`
- 默认值：`10`
- 过期阈值配置项：`AETHERFLOW_RUNTIME_HEARTBEAT_STALE_SECONDS`
- 默认值：`30`

固定判级：

- 最新 heartbeat 年龄 `<= stale_seconds`：`healthy`
- 最新 heartbeat 年龄 `> stale_seconds` 且 `<= 2 * stale_seconds`：`degraded`
- 无 heartbeat 或最新 heartbeat 年龄 `> 2 * stale_seconds`：`down`

---

## 🧩 子系统拆分

### A. 任务运行底座

**问题定义**：
当前只有表结构和 CLI 壳，没有 claim、attempt 创建和状态流转。

**目标**：
在真实 PostgreSQL 中实现 `queued -> running -> succeeded/failed` 的最小闭环。

**非目标**：
不开放对外任务查询接口，不做平台级 retry API，不做自动回收机制。

**候选方案**：

1. 内存队列
2. PostgreSQL 轮询 + `FOR UPDATE SKIP LOCKED`
3. 外部消息队列

**推荐方案**：
选 2。它与现有 v1 拓扑一致，也最容易被真实 PostgreSQL 测试证明。

### B. Artifact 最小基座

**问题定义**：
已有 `artifacts` 表，但没有文件落盘、内容读取和运行时归属表达。

**目标**：
实现本地文件存储、checksum、metadata/content API，以及 attempt-output 关联。

**非目标**：
不做 URL 抓取、不做 Playwright、不做对象存储切换。

**候选方案**：

1. 内容直接入库
2. 文件系统存内容，数据库存元数据与关联表
3. 直接上 S3 兼容对象存储

**推荐方案**：
选 2。它满足最小运行闭环，也与当前本地开发环境最匹配。

### C. Runtime Health 与 Heartbeat

**问题定义**：
当前 `/health` 只表示 API 存活，无法跨进程反映 Worker / Scheduler 状态。

**目标**：
保留现有 liveness，同时新增 `/health/summary` 聚合 Database / Worker / Scheduler 的最小健康摘要。

**非目标**：
不做外部依赖探测，不做图表，不做配置摘要平台。

**候选方案**：

1. 进程内内存状态
2. 数据库 heartbeat 快照
3. 从最近 attempt 时间反推存活

**推荐方案**：
选 2。它是当前架构下唯一稳定的跨进程状态来源。

### D. Worker / Scheduler 运行壳

**问题定义**：
当前两个 entrypoint 只有参数解析，没有真实运行语义。

**目标**：
Worker 支持 `--once` 执行一次 claim + attempt + artifact 落库；
Scheduler 支持 `--once` 写一次 heartbeat。

**非目标**：
不创建监控任务、不做批次扫描、不进入场景业务链。

**候选方案**：

1. 继续保持 no-op
2. Worker 真执行最小 runtime，Scheduler 只 heartbeat
3. 直接带上最小场景 run 写路径

**推荐方案**：
选 2。这样能证明底座可跑，又不会越界进入 3A。

---

## 🔌 Phase 2 对外接口

### 保留接口

- `GET /api/v1/platform/health`
  - 用于 API 存活检测
- `GET /api/v1/platform/health/summary`
  - 用于系统页与排障页读取最小健康摘要
- `GET /api/v1/platform/artifacts/{artifact_id}`
  - 返回 Artifact 元数据
- `GET /api/v1/platform/artifacts/{artifact_id}/content`
  - 返回 Artifact 内容

### 明确延期的接口

- `GET /api/v1/platform/tasks`
- `GET /api/v1/platform/tasks/{job_id}`
- `POST /api/v1/platform/tasks/{job_id}/retry`

延期理由：
它们依赖 `task_job -> scene_run` 的产品级稳定回查，而 Phase 2 不提前引入真实场景写路径。

---

## 💾 Phase 2 新增数据契约

### `task_attempt_artifacts`

用途：记录某次 task attempt 产出了哪些 Artifact。

约束：

- `(attempt_id, artifact_id)` 唯一
- 删除 attempt 或 artifact 时，关联关系同步清理

### `runtime_heartbeats`

用途：记录 Worker / Scheduler 的最小存活快照。

约束：

- `(role, instance_name)` 唯一
- 只存当前快照，不扩展成批次历史审计

---

## 🧪 验证策略

Phase 2 的验证必须全部基于真实 PostgreSQL，不允许切到 SQLite。

最低证据链：

1. 迁移可以在干净 PostgreSQL 上创建 `task_attempt_artifacts` 和 `runtime_heartbeats`
2. 测试夹具预置的 `task_jobs` 能被 Worker claim，并生成 `task_attempts`
3. Worker 成功后能落一个 Artifact，并写入 `task_attempt_artifacts`
4. `/api/v1/platform/artifacts/{artifact_id}` 与 `/content` 能读回内容
5. Scheduler 能写 heartbeat
6. `/api/v1/platform/health/summary` 能按固定 TTL 规则给出 `healthy/degraded/down`

---

## ⚠️ 风险与控制

### 风险 1：Phase 2 被误实现成“无 run 的平台任务系统”

**控制方式**：
- 不开放 `/platform/tasks*`
- 明确测试夹具不等于产品级写路径
- 首个真实 `task_job + scene_run` 写路径保留给 3A

### 风险 2：Health Summary 越做越宽

**控制方式**：
- 只返回 5 个字段
- `enabled_sources` / `enabled_channels` 明确延期

### 风险 3：Artifact 语义被运行时耦合污染

**控制方式**：
- `artifacts` 主表保持中立
- 运行时归属统一落到 `task_attempt_artifacts`

---

## ✅ 完成定义

满足以下条件时，Phase 2 spec 视为收口：

1. 平台公开接口边界不再与 `scene_run` 契约冲突
2. 健康摘要字段、heartbeat TTL 和判级规则已写死
3. Artifact 与 attempt 的关系通过关联表表达，不污染 `artifacts`
4. 实施计划能在不扩需求的前提下直接执行
