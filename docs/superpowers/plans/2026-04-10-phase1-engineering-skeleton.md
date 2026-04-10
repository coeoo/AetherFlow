# Phase 1 Engineering Skeleton Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 建立 `backend/ + frontend/ + infra/` 单仓工程骨架，打通可启动 API、可渲染前端路由壳、可连接 PostgreSQL 的迁移与测试基础设施。

**Architecture:** 后端使用 FastAPI + SQLAlchemy + Alembic，数据库只支持 PostgreSQL；前端使用 React + Vite 渲染平台壳与占位路由；`worker` 和 `scheduler` 在本阶段只提供可调用的 entrypoint，不承载业务执行逻辑。所有数据库测试直接连接临时 PostgreSQL，不使用 SQLite 替代。

**Tech Stack:** Python 3.11、FastAPI、SQLAlchemy 2.x、Alembic、pytest、PostgreSQL 16、React 18、TypeScript 5、Vite 6、Vitest

---

### Task 0: 隔离执行工作区，避免污染当前脏工作树

**Files:**
- Test only: 当前仓库 Git 状态

- [ ] **Step 1: 先确认当前工作树是否适合直接提交**

Run:

```bash
git status --short --branch
git diff --name-only
```

Expected:
- 能明确看到当前工作树是否仍有未提交改动

- [ ] **Step 2: 使用隔离 worktree 或已清理分支执行本计划**

Recommended path:

```bash
git worktree add ../aetherflow-phase1-exec -b phase1-skeleton <BASELINE_REF>
cd ../aetherflow-phase1-exec
```

Rules:
- 如果沿用 Phase 0 的执行 worktree，则必须确保 `git status --short` 干净后再开始 Phase 1
- 后续所有 `git commit` 步骤都只在隔离 worktree 中执行
- 如果当前仍在主工作树且目标文件已与历史改动重叠，不要执行本计划中的 commit

- [ ] **Step 3: 验证隔离工作区已经准备好**

Run:

```bash
git status --short --branch
pwd
```

Expected:
- 当前目录已经切到隔离 worktree，或至少处在一个干净可提交的执行分支

### Task 1: 建立后端环境 bootstrap

**Files:**
- Create: `backend/pyproject.toml`
- Create: `scripts/bootstrap_backend_env.sh`

- [ ] **Step 1: 先运行一个会失败的后端依赖探针**

Run:

```bash
./.venv/bin/python -c "import fastapi, sqlalchemy, alembic, psycopg"
```

Expected:
- FAIL
- 失败原因是 `.venv` 尚未创建，或后端依赖尚未安装

- [ ] **Step 2: 写出后端依赖清单与 bootstrap 脚本**

```toml
# backend/pyproject.toml
[build-system]
requires = ["setuptools>=69", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "aetherflow-backend"
version = "0.1.0"
dependencies = [
  "fastapi>=0.115,<1.0",
  "uvicorn>=0.30,<1.0",
  "sqlalchemy>=2.0,<3.0",
  "alembic>=1.14,<2.0",
  "psycopg[binary]>=3.2,<4.0",
]

[project.optional-dependencies]
dev = [
  "pytest>=8.0,<9.0",
  "httpx>=0.27,<1.0",
]

[tool.setuptools.packages.find]
where = ["."]
include = ["app*"]
```

```bash
#!/usr/bin/env bash
set -euo pipefail

python3 -m venv .venv
./.venv/bin/python -m pip install --upgrade pip
./.venv/bin/python -m pip install -e "./backend[dev]"
```

- [ ] **Step 3: 执行 bootstrap 脚本**

Run:

```bash
timeout 60s bash scripts/bootstrap_backend_env.sh
```

Expected:
- PASS
- 仓库根目录生成 `.venv`
- `backend[dev]` 依赖安装完成

- [ ] **Step 4: 重新运行依赖探针**

Run:

```bash
./.venv/bin/python -c "import fastapi, sqlalchemy, alembic, psycopg"
```

Expected:
- PASS

- [ ] **Step 5: 提交这一组变更**

```bash
git add backend/pyproject.toml scripts/bootstrap_backend_env.sh

git commit -m "chore: add backend environment bootstrap" \
  -m "What: add the backend dependency manifest, editable-install build settings, and a repeatable venv bootstrap script.
Why: all later backend tests and CLI entrypoints depend on a predictable Python environment and import path.
Validation: timeout 60s bash scripts/bootstrap_backend_env.sh && ./.venv/bin/python -c 'import fastapi, sqlalchemy, alembic, psycopg'"
```

### Task 2: 建立后端最小可启动入口

**Files:**
- Create: `backend/app/__init__.py`
- Create: `backend/app/main.py`
- Create: `backend/app/config.py`
- Create: `backend/app/api/__init__.py`
- Create: `backend/app/api/router.py`
- Create: `backend/app/api/v1/__init__.py`
- Create: `backend/app/api/v1/platform/__init__.py`
- Create: `backend/app/api/v1/platform/health.py`
- Create: `backend/tests/test_app_boot.py`

- [ ] **Step 1: 先写一个会失败的后端启动测试**

```python
from fastapi.testclient import TestClient

from app.main import create_app


def test_healthz_returns_ok() -> None:
    client = TestClient(create_app())
    response = client.get("/api/v1/platform/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
```

- [ ] **Step 2: 运行测试，确认它因应用骨架缺失而失败**

Run:

```bash
timeout 60s ./.venv/bin/python -m pytest backend/tests/test_app_boot.py -q
```

Expected:
- FAIL
- 失败原因是 `app.main`、`create_app` 或 `/healthz` 路由尚不存在

- [ ] **Step 3: 写出最小 FastAPI 应用骨架**

Create the minimal backend app structure:

```python
# backend/app/main.py
from fastapi import FastAPI

from app.api.router import api_router


def create_app() -> FastAPI:
    app = FastAPI(title="AetherFlow API")
    app.include_router(api_router)
    return app


app = create_app()
```

```python
# backend/app/api/router.py
from fastapi import APIRouter

from app.api.v1.platform.health import router as platform_health_router

api_router = APIRouter()
api_router.include_router(platform_health_router)
```

```python
# backend/app/api/v1/platform/health.py
from fastapi import APIRouter

router = APIRouter(prefix="/api/v1/platform", tags=["platform"])


@router.get("/health")
def healthz() -> dict[str, str]:
    return {"status": "ok"}
```

- [ ] **Step 4: 重新运行后端启动测试**

Run:

```bash
timeout 60s ./.venv/bin/python -m pytest backend/tests/test_app_boot.py -q
```

Expected:
- PASS

- [ ] **Step 5: 提交这一组变更**

```bash
git add backend/app/__init__.py \
  backend/app/main.py \
  backend/app/config.py \
  backend/app/api/__init__.py \
  backend/app/api/router.py \
  backend/app/api/v1/__init__.py \
  backend/app/api/v1/platform/__init__.py \
  backend/app/api/v1/platform/health.py \
  backend/tests/test_app_boot.py

git commit -m "chore: bootstrap FastAPI application shell" \
  -m "What: add app factory, root router, and a minimal healthz endpoint with a boot test.
Why: later platform phases need a stable backend entrypoint before adding PostgreSQL, worker, or scene logic.
Validation: timeout 60s ./.venv/bin/python -m pytest backend/tests/test_app_boot.py -q"
```

### Task 3: 搭建 PostgreSQL-only 数据库与迁移基础设施

**Files:**
- Create: `infra/docker-compose.dev.yml`
- Create: `backend/alembic.ini`
- Create: `backend/alembic/env.py`
- Create: `backend/alembic/script.py.mako`
- Create: `backend/alembic/versions/20260410_0001_bootstrap.py`
- Create: `backend/app/db/__init__.py`
- Create: `backend/app/db/base.py`
- Create: `backend/app/db/session.py`
- Create: `backend/app/models/__init__.py`
- Create: `backend/tests/conftest.py`
- Create: `backend/tests/test_pg_connection.py`
- Create: `backend/tests/test_migrations.py`

- [ ] **Step 1: 先写两个会失败的 PostgreSQL 测试**

```python
# backend/tests/test_pg_connection.py
from sqlalchemy import text

from app.db.session import create_engine_from_url


def test_can_connect_to_postgres(test_database_url: str) -> None:
    engine = create_engine_from_url(test_database_url)
    with engine.connect() as conn:
        assert conn.execute(text("select 1")).scalar() == 1
```

```python
# backend/tests/test_migrations.py
import subprocess
import os


def test_alembic_upgrade_head(test_database_url: str) -> None:
    env = os.environ | {"DATABASE_URL": test_database_url}
    result = subprocess.run(
        ["../.venv/bin/alembic", "upgrade", "head"],
        cwd="backend",
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
```

- [ ] **Step 2: 启动临时 PostgreSQL，并确认测试因为基础设施缺失而失败**

Run:

```bash
docker run --rm -d --name aetherflow-phase1-pg \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=aetherflow_dev \
  -p 55432:5432 postgres:16-alpine

until docker exec aetherflow-phase1-pg pg_isready -U postgres >/dev/null 2>&1; do
  sleep 1
done

export TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev
timeout 60s ./.venv/bin/python -m pytest backend/tests/test_pg_connection.py backend/tests/test_migrations.py -q
```

Expected:
- FAIL
- 失败原因是 compose、session、alembic 配置或测试 fixture 尚未存在

- [ ] **Step 3: 写出 PostgreSQL-only 连接与迁移骨架**

Implement:

```python
# backend/app/db/session.py
from sqlalchemy import create_engine


def create_engine_from_url(database_url: str):
    return create_engine(database_url, future=True)
```

```python
# backend/alembic/versions/20260410_0001_bootstrap.py
revision = "20260410_0001"
down_revision = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
```

Use `infra/docker-compose.dev.yml` to expose PostgreSQL 16 on `127.0.0.1:55432`.

- [ ] **Step 4: 重新运行 PostgreSQL 连接与迁移测试**

Run:

```bash
docker rm -f aetherflow-phase1-pg || true
docker compose -f infra/docker-compose.dev.yml up -d postgres
until docker compose -f infra/docker-compose.dev.yml exec -T postgres pg_isready -U postgres >/dev/null 2>&1; do
  sleep 1
done
export TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev
timeout 60s ./.venv/bin/python -m pytest backend/tests/test_pg_connection.py backend/tests/test_migrations.py -q
```

Expected:
- PASS
- 测试真实连接 PostgreSQL
- `alembic upgrade head` 成功执行

- [ ] **Step 5: 提交这一组变更**

```bash
git add infra/docker-compose.dev.yml \
  backend/alembic.ini \
  backend/alembic/env.py \
  backend/alembic/script.py.mako \
  backend/alembic/versions/20260410_0001_bootstrap.py \
  backend/app/db/__init__.py \
  backend/app/db/base.py \
  backend/app/db/session.py \
  backend/app/models/__init__.py \
  backend/tests/conftest.py \
  backend/tests/test_pg_connection.py \
  backend/tests/test_migrations.py

git commit -m "chore: add PostgreSQL migration foundation" \
  -m "What: add local PostgreSQL compose config, SQLAlchemy session bootstrap, Alembic config, and PG-backed tests.
Why: all later schema and task-lifecycle work depends on real PostgreSQL behavior rather than SQLite approximations.
Validation: timeout 60s ./.venv/bin/python -m pytest backend/tests/test_pg_connection.py backend/tests/test_migrations.py -q"
```

### Task 4: 提供 worker 与 scheduler 的最小 entrypoint

**Files:**
- Create: `backend/app/worker/__init__.py`
- Create: `backend/app/worker/main.py`
- Create: `backend/app/scheduler/__init__.py`
- Create: `backend/app/scheduler/main.py`
- Create: `backend/tests/test_runtime_entrypoints.py`

- [ ] **Step 1: 先写会失败的 entrypoint 测试**

```python
import subprocess
import sys


def test_worker_help_exits_zero() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "app.worker.main", "--help"],
        cwd="backend",
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_scheduler_help_exits_zero() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "app.scheduler.main", "--help"],
        cwd="backend",
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
```

- [ ] **Step 2: 运行测试，确认 entrypoint 尚未存在**

Run:

```bash
timeout 60s ./.venv/bin/python -m pytest backend/tests/test_runtime_entrypoints.py -q
```

Expected:
- FAIL
- 失败原因是 `app.worker.main` 或 `app.scheduler.main` 模块不存在

- [ ] **Step 3: 写出最小 CLI 入口，不承载业务逻辑**

Implement simple `argparse`-based entrypoints:

```python
# backend/app/worker/main.py
import argparse


def main() -> int:
    parser = argparse.ArgumentParser(prog="aetherflow-worker")
    parser.add_argument("--once", action="store_true")
    parser.parse_args()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

`backend/app/scheduler/main.py` uses the same pattern.

- [ ] **Step 4: 重新运行 entrypoint 测试**

Run:

```bash
timeout 60s ./.venv/bin/python -m pytest backend/tests/test_runtime_entrypoints.py -q
```

Expected:
- PASS

- [ ] **Step 5: 提交这一组变更**

```bash
git add backend/app/worker/__init__.py \
  backend/app/worker/main.py \
  backend/app/scheduler/__init__.py \
  backend/app/scheduler/main.py \
  backend/tests/test_runtime_entrypoints.py

git commit -m "chore: add worker and scheduler entrypoints" \
  -m "What: add importable worker and scheduler CLI entrypoints plus smoke tests.
Why: Phase 2 needs real runtime roles to hang task execution and heartbeat logic onto, even before business behavior exists.
Validation: timeout 60s ./.venv/bin/python -m pytest backend/tests/test_runtime_entrypoints.py -q"
```

### Task 5: 建立前端 Vite 路由壳

**Files:**
- Create: `frontend/package.json`
- Create: `frontend/tsconfig.json`
- Create: `frontend/vite.config.ts`
- Create: `frontend/vitest.config.ts`
- Create: `frontend/index.html`
- Create: `frontend/src/main.tsx`
- Create: `frontend/src/app/router.tsx`
- Create: `frontend/src/app/providers.tsx`
- Create: `frontend/src/app/query-client.ts`
- Create: `frontend/src/routes/HomePage.tsx`
- Create: `frontend/src/routes/CVELookupPage.tsx`
- Create: `frontend/src/routes/CVERunDetailPage.tsx`
- Create: `frontend/src/routes/AnnouncementWorkbenchPage.tsx`
- Create: `frontend/src/routes/AnnouncementSourcesPage.tsx`
- Create: `frontend/src/routes/AnnouncementMonitorPage.tsx`
- Create: `frontend/src/routes/AnnouncementRunDetailPage.tsx`
- Create: `frontend/src/routes/DeliveryCenterPage.tsx`
- Create: `frontend/src/routes/SystemHealthPage.tsx`
- Create: `frontend/src/routes/TaskCenterPage.tsx`
- Create: `frontend/src/test/setup.ts`
- Create: `frontend/src/test/router.test.tsx`

- [ ] **Step 1: 先写会失败的前端路由测试**

```tsx
import { render, screen } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router-dom";

import { routes } from "../app/router";

test.each([
  ["/", "平台首页"],
  ["/cve", "CVE 检索工作台"],
  ["/announcements", "安全公告工作台"],
  ["/announcements?tab=monitoring", "安全公告工作台"],
  ["/deliveries", "投递中心"],
  ["/system/tasks", "平台任务中心"],
  ["/system/health", "系统状态"],
])("renders route shell for %s", async (path, heading) => {
  const router = createMemoryRouter(routes, {
    initialEntries: [path],
  });

  render(<RouterProvider router={router} />);

  expect(await screen.findByText(heading)).toBeInTheDocument();
});
```

- [ ] **Step 2: 运行测试，确认前端骨架尚不存在**

Run:

```bash
timeout 60s npm --prefix frontend test -- --run src/test/router.test.tsx
```

Expected:
- FAIL
- 失败原因是前端依赖、router 或 route components 尚未存在

- [ ] **Step 3: 建立最小前端工程与路由占位页**

Pin the minimum frontend dependency matrix first:

```json
{
  "name": "aetherflow-frontend",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "test": "vitest"
  },
  "dependencies": {
    "@tanstack/react-query": "^5.59.0",
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "react-router-dom": "^6.28.0"
  },
  "devDependencies": {
    "@testing-library/jest-dom": "^6.6.3",
    "@testing-library/react": "^16.0.1",
    "@types/react": "^18.3.12",
    "@types/react-dom": "^18.3.1",
    "@vitejs/plugin-react": "^4.3.3",
    "jsdom": "^25.0.1",
    "typescript": "^5.6.3",
    "vite": "^6.0.1",
    "vitest": "^2.1.5"
  }
}
```

Implement a route shell covering the phase-1 visible paths:

```tsx
// frontend/src/app/router.tsx
import { RouteObject } from "react-router-dom";

import { HomePage } from "../routes/HomePage";
import { CVELookupPage } from "../routes/CVELookupPage";
import { CVERunDetailPage } from "../routes/CVERunDetailPage";
import { AnnouncementWorkbenchPage } from "../routes/AnnouncementWorkbenchPage";
import { AnnouncementSourcesPage } from "../routes/AnnouncementSourcesPage";
import { AnnouncementRunDetailPage } from "../routes/AnnouncementRunDetailPage";
import { DeliveryCenterPage } from "../routes/DeliveryCenterPage";
import { SystemHealthPage } from "../routes/SystemHealthPage";
import { TaskCenterPage } from "../routes/TaskCenterPage";

export const routes: RouteObject[] = [
  { path: "/", element: <HomePage /> },
  { path: "/cve", element: <CVELookupPage /> },
  { path: "/cve/runs/:runId", element: <CVERunDetailPage /> },
  { path: "/announcements", element: <AnnouncementWorkbenchPage /> },
  { path: "/announcements/sources", element: <AnnouncementSourcesPage /> },
  { path: "/announcements/runs/:runId", element: <AnnouncementRunDetailPage /> },
  { path: "/deliveries", element: <DeliveryCenterPage /> },
  { path: "/system/tasks", element: <TaskCenterPage /> },
  { path: "/system/health", element: <SystemHealthPage /> },
];
```

Also create:
- `frontend/src/app/query-client.ts` as the canonical TanStack Query setup point
- `frontend/src/app/providers.tsx` to mount `QueryClientProvider` from `@tanstack/react-query`
- `frontend/src/routes/AnnouncementMonitorPage.tsx` as the reserved page module for later monitoring-tab extraction; Phase 1 先让 `/announcements?tab=monitoring` 复用 `/announcements` 占位页，避免提前引入监控页逻辑

Each placeholder page only needs one stable heading for now.

- [ ] **Step 4: 安装依赖并重新运行前端测试与构建**

Run:

```bash
npm --prefix frontend install
timeout 60s npm --prefix frontend test -- --run src/test/router.test.tsx
timeout 60s npm --prefix frontend run build
```

Expected:
- 测试 PASS
- 构建 PASS

- [ ] **Step 5: 提交这一组变更**

```bash
git add frontend/package.json \
  frontend/tsconfig.json \
  frontend/vite.config.ts \
  frontend/vitest.config.ts \
  frontend/index.html \
  frontend/src/main.tsx \
  frontend/src/app/router.tsx \
  frontend/src/app/providers.tsx \
  frontend/src/app/query-client.ts \
  frontend/src/routes/HomePage.tsx \
  frontend/src/routes/CVELookupPage.tsx \
  frontend/src/routes/CVERunDetailPage.tsx \
  frontend/src/routes/AnnouncementWorkbenchPage.tsx \
  frontend/src/routes/AnnouncementSourcesPage.tsx \
  frontend/src/routes/AnnouncementMonitorPage.tsx \
  frontend/src/routes/AnnouncementRunDetailPage.tsx \
  frontend/src/routes/DeliveryCenterPage.tsx \
  frontend/src/routes/SystemHealthPage.tsx \
  frontend/src/routes/TaskCenterPage.tsx \
  frontend/src/test/setup.ts \
  frontend/src/test/router.test.tsx

git commit -m "chore: scaffold frontend route shell" \
  -m "What: add a Vite/React frontend skeleton with route placeholders for the platform shell and first scene entry paths.
Why: later phases need stable URLs and a renderable shell before wiring real API-backed views.
Validation: timeout 60s npm --prefix frontend test -- --run src/test/router.test.tsx && timeout 60s npm --prefix frontend run build"
```

### Task 6: 提供统一的开发与验证入口

**Files:**
- Create: `Makefile`

- [ ] **Step 1: 先运行一个会失败的仓库级验证命令**

Run:

```bash
timeout 60s make phase1-verify
```

Expected:
- FAIL
- 失败原因是仓库里还没有统一的 `phase1-verify` 目标

- [ ] **Step 2: 添加最小 Makefile，把 Phase 1 关键命令收口**

```makefile
.PHONY: backend-install frontend-install pg-up pg-down backend-test frontend-test phase1-verify

VENV_PYTHON := ./.venv/bin/python
TEST_DATABASE_URL ?= postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev

backend-install:
	timeout 60s bash scripts/bootstrap_backend_env.sh

frontend-install:
	npm --prefix frontend install

pg-up:
	docker compose -f infra/docker-compose.dev.yml up -d postgres
	until docker compose -f infra/docker-compose.dev.yml exec -T postgres pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done

pg-down:
	docker compose -f infra/docker-compose.dev.yml down -v

backend-test:
	TEST_DATABASE_URL=$(TEST_DATABASE_URL) timeout 60s $(VENV_PYTHON) -m pytest backend/tests -q

frontend-test:
	timeout 60s npm --prefix frontend test -- --run

phase1-verify: pg-up
	TEST_DATABASE_URL=$(TEST_DATABASE_URL) timeout 60s $(VENV_PYTHON) -m pytest backend/tests -q
	timeout 60s npm --prefix frontend test -- --run
	timeout 60s npm --prefix frontend run build
```

- [ ] **Step 3: 运行仓库级验证命令**

Run:

```bash
make backend-install frontend-install
timeout 60s make phase1-verify
```

Expected:
- PASS
- 后端测试、前端测试、前端构建都通过

- [ ] **Step 4: 检查工作区与最终证据**

Run:

```bash
git status --short
git diff --check
git diff --stat -- backend frontend infra Makefile
```

Expected:
- 没有 whitespace error
- 只包含 Phase 1 定义的骨架文件

- [ ] **Step 5: 提交这一组变更**

```bash
git add Makefile

git commit -m "chore: add phase1 verification entrypoints" \
  -m "What: add a Makefile to standardize PostgreSQL startup, backend tests, frontend tests, and the phase1 verification flow.
Why: implementation after this phase should have one obvious way to prove the skeleton still boots and builds.
Validation: make backend-install frontend-install && timeout 60s make phase1-verify"
```

### Task 7: 做 Phase 1 的最终验收

**Files:**
- Test only: `backend/tests/*`
- Test only: `frontend/src/test/*`
- Test only: `Makefile`

- [ ] **Step 1: 启动 PostgreSQL 并跑完整后端测试**

Run:

```bash
docker compose -f infra/docker-compose.dev.yml up -d postgres
until docker compose -f infra/docker-compose.dev.yml exec -T postgres pg_isready -U postgres >/dev/null 2>&1; do
  sleep 1
done
export TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev
timeout 60s ./.venv/bin/python -m pytest backend/tests -q
```

Expected:
- PASS

- [ ] **Step 2: 跑完整前端测试与构建**

Run:

```bash
timeout 60s npm --prefix frontend test -- --run
timeout 60s npm --prefix frontend run build
```

Expected:
- PASS

- [ ] **Step 3: 验证最小运行入口**

Run:

```bash
timeout 60s ./.venv/bin/python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 18080 &
UVICORN_PID=$!
sleep 2
curl -s http://127.0.0.1:18080/api/v1/platform/health
kill "$UVICORN_PID"
```

Expected:
- 返回 `{"status":"ok"}`

- [ ] **Step 4: 记录 Phase 1 完成结论**

Completion criteria:
- FastAPI app 可启动并返回 `/api/v1/platform/health`
- Alembic 能在真实 PostgreSQL 上 `upgrade head`
- `worker` 和 `scheduler` entrypoint 可被调用
- 前端路由壳可渲染 `/`、`/cve`、`/cve/runs/:runId`、`/announcements`、`/announcements?tab=monitoring`、`/announcements/sources`、`/announcements/runs/:runId`、`/deliveries`、`/system/tasks`、`/system/health`
- 仓库级 `make phase1-verify` 可在 60 秒门限内完成

### Phase 1 执行结果（2026-04-10）

- `timeout 60s make phase1-verify`：通过
- `timeout 60s bash -lc './.venv/bin/python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 18080 >/tmp/aetherflow_uvicorn.log 2>&1 & ... ; curl -sS http://127.0.0.1:18080/api/v1/platform/health'`：返回 `{"status":"ok"}`

结果摘要：

- 后端测试：`8 passed`
- 前端测试：`14 passed`
- 前端构建：Vite build 通过

结论：

- Phase 1 的工程骨架、统一验证入口和最小运行入口已按计划落地。
- 当前通过的是“平台工程骨架验收”，不是 CVE 或安全公告业务链路已经完成。
