# 安全公告 Phase 1 + Phase 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在当前 `AetherFlow` 仓库中落地安全公告的第一条真实业务闭环：公告核心模型 + Openwall 单源监控闭环。

**Architecture:** 本轮实现采用“行为迁移 + 平台重写”。后端围绕 `announcement_sources -> source_fetch_records -> announcement_runs -> announcement_documents -> announcement_intelligence_packages` 建模，旧项目只作为 Openwall 抓取行为和 Linux 相关性判定逻辑的参考来源，不迁入其 RSS / JSON / 单体任务执行结构。前端只把公告工作台、来源页和详情页从占位状态提升为最小真实数据页。

**Tech Stack:** Python 3.11、FastAPI、SQLAlchemy 2.x、Alembic、pytest、httpx、BeautifulSoup、React 18、TanStack Query、Vitest

---

## 文件结构

### 后端新增

- `backend/app/models/announcement.py`
  - 公告域模型
- `backend/app/announcements/__init__.py`
  - 公告场景模块入口
- `backend/app/announcements/service.py`
  - run/source 创建与查询
- `backend/app/announcements/detail_service.py`
  - 公告详情聚合
- `backend/app/announcements/runtime.py`
  - Worker 公告运行时
- `backend/app/announcements/openwall_adapter.py`
  - Openwall 标准化适配器
- `backend/app/announcements/intelligence.py`
  - Linux relevance 与摘要生成
- `backend/app/api/v1/announcements/__init__.py`
  - 路由包入口
- `backend/app/api/v1/announcements/runs.py`
  - run API
- `backend/app/api/v1/announcements/sources.py`
  - source 与 run-now API
- `backend/alembic/versions/20260415_0003_announcement_phase1_phase2.py`
  - 公告域迁移

### 后端修改

- `backend/app/models/__init__.py`
- `backend/app/api/router.py`
- `backend/app/worker/runtime.py`
- `backend/tests/conftest.py`
- `backend/tests/test_migrations.py`

### 后端测试

- `backend/tests/test_announcement_schema_contract.py`
- `backend/tests/test_announcement_api.py`
- `backend/tests/test_announcement_runtime.py`
- `backend/tests/test_openwall_adapter.py`

### 前端新增

- `frontend/src/features/announcements/types.ts`
- `frontend/src/features/announcements/api.ts`
- `frontend/src/features/announcements/hooks.ts`

### 前端修改

- `frontend/src/routes/AnnouncementWorkbenchPage.tsx`
- `frontend/src/routes/AnnouncementSourcesPage.tsx`
- `frontend/src/routes/AnnouncementRunDetailPage.tsx`
- `frontend/src/test/router.test.tsx`

### 前端测试

- `frontend/src/test/announcement-pages.test.tsx`

---

### Task 1: 公告域数据模型与迁移

**Files:**
- Create: `backend/app/models/announcement.py`
- Modify: `backend/app/models/__init__.py`
- Create: `backend/alembic/versions/20260415_0003_announcement_phase1_phase2.py`
- Test: `backend/tests/test_announcement_schema_contract.py`
- Modify: `backend/tests/test_migrations.py`

- [ ] **Step 1: 先写失败测试，锁定公告域模型契约**

在 `backend/tests/test_announcement_schema_contract.py` 中先写：

```python
def test_announcement_metadata_contains_expected_tables() -> None:
    ...


def test_announcement_run_has_unique_job_binding() -> None:
    ...


def test_announcement_document_keeps_source_and_normalized_artifact_refs() -> None:
    ...
```

- [ ] **Step 2: 扩展迁移测试，先让它失败**

在 `backend/tests/test_migrations.py` 中新增对以下表的断言：

```python
{
    "announcement_sources",
    "announcement_runs",
    "announcement_documents",
    "announcement_intelligence_packages",
}
```

- [ ] **Step 3: 运行失败测试**

Run:

```bash
TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev \
timeout 60s ./.venv/bin/python -m pytest \
  backend/tests/test_announcement_schema_contract.py \
  backend/tests/test_migrations.py -q
```

Expected:
- FAIL
- 原因是公告域模型和迁移尚未实现

- [ ] **Step 4: 最小实现公告模型**

实现 `backend/app/models/announcement.py`：

- `AnnouncementSource`
- `AnnouncementRun`
- `AnnouncementDocument`
- `AnnouncementIntelligencePackage`

关键要求：

- `AnnouncementRun.job_id` 唯一绑定 `task_jobs`
- `AnnouncementDocument.run_id` 唯一绑定 `announcement_runs`
- `AnnouncementIntelligencePackage.run_id/document_id` 唯一绑定
- Artifact 引用字段保持可空外键

- [ ] **Step 5: 写 Alembic 迁移**

迁移必须创建：

- `announcement_sources`
- `announcement_runs`
- `announcement_documents`
- `announcement_intelligence_packages`

并保持字段名与 SQL 草案一致：

- `entry_mode`
- `trigger_fetch_id`
- `source_item_key`
- `content_dedup_hash`
- `source_artifact_id`
- `normalized_text_artifact_id`

- [ ] **Step 6: 跑测试到绿**

Run:

```bash
TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev \
timeout 60s ./.venv/bin/python -m pytest \
  backend/tests/test_announcement_schema_contract.py \
  backend/tests/test_migrations.py -q
```

Expected:
- PASS

---

### Task 2: 公告 run API 与详情聚合

**Files:**
- Create: `backend/app/announcements/service.py`
- Create: `backend/app/announcements/detail_service.py`
- Create: `backend/app/api/v1/announcements/__init__.py`
- Create: `backend/app/api/v1/announcements/runs.py`
- Modify: `backend/app/api/router.py`
- Test: `backend/tests/test_announcement_api.py`

- [ ] **Step 1: 先写 run API 失败测试**

在 `backend/tests/test_announcement_api.py` 中先写：

```python
def test_post_announcement_runs_creates_manual_url_run_and_task_job(client, db_session) -> None:
    ...


def test_get_announcement_run_returns_detail_payload(client, db_session) -> None:
    ...


def test_get_announcement_run_returns_404_for_missing_run(client) -> None:
    ...
```

首轮请求体固定为：

```json
{
  "input_mode": "url",
  "source_url": "https://example.com/advisory"
}
```

- [ ] **Step 2: 运行测试确认失败**

Run:

```bash
TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev \
timeout 60s ./.venv/bin/python -m pytest backend/tests/test_announcement_api.py -q
```

Expected:
- FAIL

- [ ] **Step 3: 实现最小 service**

在 `backend/app/announcements/service.py` 中实现：

- `create_announcement_run(...)`
- `get_announcement_run(...)`
- `list_announcement_sources(...)`
- `get_announcement_source(...)`

`create_announcement_run` 要同时创建：

- `TaskJob(scene_name="announcement", job_type="announcement_manual_extract")`
- `AnnouncementRun(entry_mode="manual_url", status="queued", stage="fetch_source")`

- [ ] **Step 4: 实现最小详情聚合**

在 `backend/app/announcements/detail_service.py` 中返回：

- run 基本信息
- document 基本信息
- package 基本信息
- progress 最小字段

- [ ] **Step 5: 实现 API 路由并接到总路由**

新增：

- `POST /api/v1/announcements/runs`
- `GET /api/v1/announcements/runs/{run_id}`

- [ ] **Step 6: 跑测试到绿**

Run:

```bash
TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev \
timeout 60s ./.venv/bin/python -m pytest backend/tests/test_announcement_api.py -q
```

Expected:
- PASS

---

### Task 3: Openwall 适配器与监控源 `run-now`

**Files:**
- Create: `backend/app/announcements/openwall_adapter.py`
- Modify: `backend/app/announcements/service.py`
- Create: `backend/app/api/v1/announcements/sources.py`
- Test: `backend/tests/test_openwall_adapter.py`
- Modify: `backend/tests/test_announcement_api.py`

- [ ] **Step 1: 先写 Openwall adapter 失败测试**

在 `backend/tests/test_openwall_adapter.py` 中写：

```python
def test_openwall_adapter_extracts_non_reply_messages_from_daily_index(...) -> None:
    ...


def test_openwall_adapter_fetches_message_body_and_returns_standard_document(...) -> None:
    ...


def test_openwall_adapter_builds_stable_source_item_key_from_message_url(...) -> None:
    ...
```

- [ ] **Step 2: 先写 `run-now` API 失败测试**

在 `backend/tests/test_announcement_api.py` 中新增：

```python
def test_get_announcement_sources_returns_configured_sources(...) -> None:
    ...


def test_post_run_now_creates_monitor_job_for_source(...) -> None:
    ...
```

- [ ] **Step 3: 运行测试确认失败**

Run:

```bash
TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev \
timeout 60s ./.venv/bin/python -m pytest \
  backend/tests/test_openwall_adapter.py \
  backend/tests/test_announcement_api.py -q
```

Expected:
- FAIL

- [ ] **Step 4: 实现 Openwall adapter**

最小实现要求：

- 支持抓取日列表页
- 过滤 `Re:` 回复
- 过滤重复标题
- 抓取消息页正文
- 输出 `StandardSourceDocument`

不要做：

- RSS 生成
- JSON 去重文件

- [ ] **Step 5: 实现 source API**

新增：

- `GET /api/v1/announcements/sources`
- `POST /api/v1/announcements/sources/{source_id}/run-now`

`run-now` 只需：

- 为 source 创建 `TaskJob(scene_name="announcement", job_type="announcement_monitor_fetch")`
- payload 中带 `source_id`

- [ ] **Step 6: 跑测试到绿**

Run:

```bash
TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev \
timeout 60s ./.venv/bin/python -m pytest \
  backend/tests/test_openwall_adapter.py \
  backend/tests/test_announcement_api.py -q
```

Expected:
- PASS

---

### Task 4: Worker 公告运行时与单源监控闭环

**Files:**
- Create: `backend/app/announcements/runtime.py`
- Create: `backend/app/announcements/intelligence.py`
- Modify: `backend/app/worker/runtime.py`
- Test: `backend/tests/test_announcement_runtime.py`

- [ ] **Step 1: 先写 Worker 失败测试**

在 `backend/tests/test_announcement_runtime.py` 中写：

```python
def test_worker_processes_manual_announcement_run_and_creates_document_and_package(...) -> None:
    ...


def test_worker_processes_openwall_monitor_job_and_creates_fetch_record_and_runs(...) -> None:
    ...


def test_worker_does_not_create_duplicate_runs_for_same_source_item_key(...) -> None:
    ...
```

- [ ] **Step 2: 运行测试确认失败**

Run:

```bash
TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev \
timeout 60s ./.venv/bin/python -m pytest backend/tests/test_announcement_runtime.py -q
```

Expected:
- FAIL

- [ ] **Step 3: 实现最小 intelligence 逻辑**

首轮只实现：

- `classify_linux_relevance(title: str, content: str) -> tuple[bool | None, float, str]`

规则：

- 先用确定性关键词兜底
- 暂不接真实模型调用
- 返回：
  - `linux_related`
  - `confidence`
  - `analyst_summary`

- [ ] **Step 4: 实现 manual runtime**

对于 `announcement_manual_extract`：

- 读取 `source_url`
- 抓取页面正文
- 保存 source Artifact
- 归一化文本并保存 normalized Artifact
- 创建 document
- 创建 package
- 收口 run

- [ ] **Step 5: 实现 monitor runtime**

对于 `announcement_monitor_fetch`：

- 创建 `SourceFetchRecord`
- 调用 adapter
- 根据 `(source_id, source_item_key)` 过滤已存在文档
- 为新增文档创建新的 `announcement_manual_extract` job + run

- [ ] **Step 6: 扩展 worker/runtime.py**

让 worker 同时支持：

- `announcement_manual_extract`
- `announcement_monitor_fetch`

- [ ] **Step 7: 跑测试到绿**

Run:

```bash
TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev \
timeout 60s ./.venv/bin/python -m pytest backend/tests/test_announcement_runtime.py -q
```

Expected:
- PASS

---

### Task 5: 公告前端最小真实页面

**Files:**
- Create: `frontend/src/features/announcements/types.ts`
- Create: `frontend/src/features/announcements/api.ts`
- Create: `frontend/src/features/announcements/hooks.ts`
- Modify: `frontend/src/routes/AnnouncementWorkbenchPage.tsx`
- Modify: `frontend/src/routes/AnnouncementSourcesPage.tsx`
- Modify: `frontend/src/routes/AnnouncementRunDetailPage.tsx`
- Create: `frontend/src/test/announcement-pages.test.tsx`

- [ ] **Step 1: 先写前端失败测试**

测试覆盖：

```tsx
test("announcement workbench can submit url mode and show latest run preview", async () => {
  ...
})

test("announcement sources page loads source list and exposes run-now action", async () => {
  ...
})

test("announcement detail page renders package summary from api payload", async () => {
  ...
})
```

- [ ] **Step 2: 运行测试确认失败**

Run:

```bash
timeout 60s npm --prefix frontend test -- --run src/test/announcement-pages.test.tsx
```

Expected:
- FAIL

- [ ] **Step 3: 实现前端 API / hooks**

最小 API：

- `createAnnouncementRun`
- `getAnnouncementRunDetail`
- `getAnnouncementSources`
- `runAnnouncementSourceNow`

- [ ] **Step 4: 改造工作台页**

要求：

- 默认提供 URL 输入
- 提交后展示 run 状态与摘要
- `?tab=monitoring` 展示来源列表或最近批次的最小摘要

- [ ] **Step 5: 改造来源页**

要求：

- 展示 source list
- 每条 source 有 `立即试跑`

- [ ] **Step 6: 改造详情页**

要求：

- 展示 run 状态
- 展示标题 / 来源 / Linux 相关性 / confidence / summary

- [ ] **Step 7: 跑测试到绿**

Run:

```bash
timeout 60s npm --prefix frontend test -- --run src/test/announcement-pages.test.tsx
```

Expected:
- PASS

---

### Task 6: 端到端验证与收口

**Files:**
- Modify only if needed: 修复测试暴露的问题

- [ ] **Step 1: 跑后端公告全量测试**

Run:

```bash
TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev \
timeout 60s ./.venv/bin/python -m pytest \
  backend/tests/test_announcement_schema_contract.py \
  backend/tests/test_announcement_api.py \
  backend/tests/test_openwall_adapter.py \
  backend/tests/test_announcement_runtime.py \
  backend/tests/test_migrations.py -q
```

Expected:
- PASS

- [ ] **Step 2: 跑前端公告测试**

Run:

```bash
timeout 60s npm --prefix frontend test -- --run \
  src/test/announcement-pages.test.tsx \
  src/test/router.test.tsx
```

Expected:
- PASS

- [ ] **Step 3: 做最小启动验证**

Run:

```bash
timeout 60s ./.venv/bin/python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 18081 &
UVICORN_PID=$!
sleep 2
curl -s http://127.0.0.1:18081/api/v1/platform/health
kill "$UVICORN_PID"
wait "$UVICORN_PID" 2>/dev/null || true
```

Expected:
- 返回健康检查成功结果

- [ ] **Step 4: 检查最终变更范围**

Run:

```bash
git status --short
git diff --stat
```

Expected:
- 只包含公告 Phase 1 + Phase 2 相关文件

---

## 完成标准

- 公告域迁移可升级到 `head`
- 手动 URL run 可创建并返回详情
- Openwall 源可 `run-now`
- Monitor fetch 会为新增文档创建单文档 run
- Worker 能消费公告任务
- 公告前端页具备最小真实数据能力
- 后端与前端测试全部通过
