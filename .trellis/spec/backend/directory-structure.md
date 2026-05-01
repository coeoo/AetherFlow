# Backend 目录结构

> AetherFlow 后端模块组织约定。AI 子代理写新代码前必须按本文档定位文件。

---

## 1. 顶层布局

`backend/app/` 下按"承载平台 / 场景 / 共享底座"三类组织：

| 目录 | 类别 | 职责 |
|------|------|------|
| `app/main.py` | 入口 | `create_app()` 构建 FastAPI，装配 `api_router` |
| `app/api/` | 接入层 | HTTP 路由聚合与版本化（`api/router.py` + `api/v1/*`） |
| `app/config.py` | 共享底座 | `load_settings()` 从 `.env.local` + 环境变量构建 `Settings` dataclass |
| `app/db/` | 共享底座 | SQLAlchemy 引擎、Session 工厂、Alembic 迁移基线（`base.py` 提供 `Base`） |
| `app/models/` | 共享底座 | ORM 模型按场景拆分：`cve.py` / `announcement.py` / `platform.py` |
| `app/platform/` | 平台层 | 平台共用能力：`home_summary`、`health_summary`、`task_runtime` 等。**禁止出现 CVE 或 announcement 语义命名** |
| `app/cve/` | 场景层 | CVE Patch 检索：LangGraph + Playwright Agent 主链 |
| `app/announcements/` | 场景层 | 安全公告手动提取与监控批次 |
| `app/worker/` | 执行层 | Worker entrypoint 与任务领取（`runtime.py::process_once`） |
| `app/scheduler/` | 执行层 | Scheduler entrypoint，**最小职责**：heartbeat + 到期投递处理 |
| `app/http_client.py` | 共享底座 | 统一 HTTP 客户端（外部抓取共用） |

---

## 2. 关键入口

- **API 装配**：`backend/app/main.py::create_app` → `backend/app/api/router.py::api_router`
- **路由聚合**：`backend/app/api/router.py` 是唯一聚合点，按场景 + 平台分组 include
- **CVE 场景图运行时**：`backend/app/cve/agent_graph.py::build_cve_patch_graph`
- **CVE 节点实现**：`backend/app/cve/agent_nodes.py`（resolve_seeds / build_initial_frontier / fetch_next_batch / extract_links_and_candidates / agent_decide / download_and_validate / finalize_run）
- **Worker 主循环**：`backend/app/worker/runtime.py`（按 `scene_name + job_type` 分派到具体 runtime）
- **Scheduler 真相**：`backend/app/scheduler/runtime.py`（不要扩写为完整调度平台）

---

## 3. 模块边界规则

1. **平台层不允许出现场景语义命名**（来自 `docs/06-开发规范/代码规范.md` §2）。
   - 反例：`platform/cve_summary.py`
   - 正例：`platform/home_summary.py`（按 scene_name 字段分支聚合）
2. **场景层各自维护 model / service / route / schema**。
   - CVE：`app/cve/service.py`、`app/cve/runtime.py`、`app/api/v1/cve/runs.py`、`app/models/cve.py`
   - 公告：对应位置同名子模块
   - **禁止**用单个"通用 run/result"类硬合并两个场景。
3. **大内容走 Artifact**：原始 HTML、patch、diff 不直接堆进业务表响应字段，统一沉淀到 Artifact 存储（`backend/.runtime/artifacts/`，由 `app/config.py::DEFAULT_ARTIFACT_ROOT` 计算）。
4. **决策与工具拆分**（CVE 场景）：
   - `app/cve/decisions/{navigation,fallback,candidate_judge}.py` — 决策层
   - `app/cve/agent_search_tools.py`、`app/cve/browser/*` — 工具层
   - `app/cve/agent_nodes.py` 只负责图节点编排，不写决策细节

---

## 4. 命名约定

- **文件**：`snake_case.py`，例如 `agent_nodes.py`、`patch_evidence.py`
- **类**：`PascalCase`，场景类必须带场景前缀：`CVERun`、`AnnouncementRun`、`SourceFetchRecord`
- **函数**：`snake_case`，长任务节点函数以 `_node` 结尾：`resolve_seeds_node`
- **环境变量**：项目自有变量统一前缀 `AETHERFLOW_`，例如 `AETHERFLOW_CVE_CANDIDATE_JUDGE_ENABLED`
- **logger 名**：模块级 `_logger = logging.getLogger(__name__)`（参考 `backend/app/cve/runtime.py:24`）
- **测试文件**：`backend/tests/test_<module>.py`，acceptance 类前缀 `test_acceptance_*`

---

## 5. 禁止

- 不要在 `backend/results/` 写代码或测试夹具（运行证据目录，默认 git 忽略，参见 `AGENTS.md` §3.3）。
- 不要把场景语义函数（`get_cve_*`）放进 `app/platform/`。
- 不要在 `app/scheduler/runtime.py` 里写完整调度逻辑（违反"最小职责"约束）。
- 不要复活旧 `pipeline/product/diagnostics` 命名（参见 `docs/03-系统架构/架构设计.md` §设计原则）。

---

## 6. 长期实现细节去哪写

- **协作规则、阶段性事实、入口索引** → `AGENTS.md`
- **模块级源码复刻级设计** → `docs/design/<topic>.md`（按 `docs/design/README.md` 的模板）
- **执行计划、Phase 推进** → 任务级 `prd.md` 或 `docs/design/<adr>.md` 的 execution plan 段
- **本 spec** → 只承载"AI 子代理写代码前必须知道的目录/边界/命名约定"
