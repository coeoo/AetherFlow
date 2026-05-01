# Backend 数据库约定

> ORM、迁移、查询、测试数据库的真实模式。

---

## 1. 技术栈

- **数据库**：PostgreSQL（v1 唯一后端，参见 `docs/03-系统架构/架构设计.md`）
- **ORM**：SQLAlchemy 2.x（仓库实际是 sync session，不是 async；参见 `backend/app/db/session.py::create_session_factory`）
- **迁移**：Alembic 1.14.x（配置 `backend/alembic.ini`，迁移目录 `backend/alembic/`）
- **校验序列化**：Pydantic 2.x

> 注意：`docs/superpowers` 里的旧设计提到过 async session，但当前 `backend/app/db/session.py` 仍是 sync。新代码请按 sync 写，跨场景统一。

---

## 2. 引擎与 Session

入口：

- `backend/app/db/session.py::create_engine_from_url(url)` — 创建 engine（带 LRU cache）
- `backend/app/db/session.py::create_session_factory(url)` — 返回 sessionmaker（带 LRU cache）
- `backend/app/config.py::load_settings().database_url` — 真实 URL 来源

调用模式（参考 `backend/app/api/v1/cve/runs.py::create_run`）：

```python
settings = load_settings()
session_factory = create_session_factory(settings.database_url)
with session_factory() as session:
    run = create_cve_run(session, cve_id=payload.cve_id)
    session.commit()
    session.refresh(run)
```

不要在 service 层 `import create_session_factory` 自建 session；service 接受 session 作为参数。

---

## 3. 模型组织

- 所有 ORM 模型继承 `backend/app/db/base.py::Base`
- 按场景文件拆分：
  - `backend/app/models/cve.py` — `CVERun`、`CVEPatchArtifact` 等
  - `backend/app/models/announcement.py` — `AnnouncementRun`、`SourceFetchRecord` 等
  - `backend/app/models/platform.py` — `TaskJob`、`TaskAttempt`、`Delivery` 等
- `backend/app/models/__init__.py` 统一 re-export，方便 `from app.models import CVERun, TaskJob`
- 类名必须带场景前缀（参见 `代码规范.md` §3）

---

## 4. Alembic 迁移

- 迁移文件位置：`backend/alembic/versions/`
- 命令需在 `backend/` 目录或显式 `-c backend/alembic.ini` 下跑
- 数据库变更要求同步更新 `docs/03-系统架构/数据库设计.md`（参见 `代码规范.md` §9）

---

## 5. 测试数据库

测试通过 `TEST_DATABASE_URL` 环境变量隔离（参见 `AGENTS.md` §3.4）：

- **默认值**（`Makefile`）：`postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev`
- **启动顺序**：`make pg-up` → `make backend-test`
- **测试 fixture**（`backend/tests/conftest.py`）：
  - `test_database_url` — 缺失环境变量时 `pytest.skip()`，**不要**静默继续
  - `db_session` — 每用例 reset public schema 后注入新 session
  - `client` — 注入了测试 DB 的 FastAPI TestClient
  - `seeded_cve_run` — 预置 CVE run + TaskJob 的复合 fixture
- **schema reset**：`reset_database()` 用 `DROP SCHEMA IF EXISTS public CASCADE` + `CREATE EXTENSION pgcrypto`，并清掉 LRU 缓存的 engine/session factory

---

## 6. 查询模式

- 大字段（HTML、patch、diff、JSON 详情）：JSONB 列或独立 Artifact 存储，**不**直接进业务表行
- 高频查询字段建索引（`docs/03-系统架构/架构设计.md` §性能设计）
- 跨场景查询要走平台层聚合（`app/platform/home_summary.py`），不要在场景模块互相 import

---

## 7. 禁止

- **不要在测试中静默吞 PostgreSQL 连接错误**。`test_database_url` fixture 已经做了显式 skip；其他 DB 错误必须冒泡。
- **不要在测试用例之间共享 session 状态**。每个用例都应该通过 `db_session` fixture 重新建 session（schema 也会重建）。
- **不要硬编码连接串**。一律走 `os.environ['TEST_DATABASE_URL']` 或 `Settings.database_url`。
- **不要绕过 Alembic 直接 `Base.metadata.create_all`**（生产环境）。测试环境用 `create_all` 是 OK 的，参见 `conftest.py::reset_database`。
- **数据库变更**忘了更新 `docs/03-系统架构/数据库设计.md` 是常见漏。
