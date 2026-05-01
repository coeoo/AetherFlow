# 当前项目分析记录

> 仅基于本地代码与当前工作区状态，未做外部检索。

## 1. 仓库与运行基线

- 仓库根目录：`/opt/projects/demo/aetherflow`
- 当前分支：`main`
- 当前存在大量未提交改动，主要集中在：
  - `backend/app/cve/*`
  - `backend/tests/*`
  - `docs/design/*`
  - `docs/superpowers/*`
- 运行形态仍是单仓前后端结构：
  - 后端：FastAPI + SQLAlchemy + PostgreSQL + Playwright + LangGraph
  - 前端：React + React Router

## 2. 主要入口与分层

### 后端入口

- `backend/app/main.py`
  - `create_app()` 通过 `app.include_router(api_router)` 挂载全部 API。
- `backend/app/api/router.py`
  - 聚合三组路由：
    - `cve`
    - `announcements`
    - `platform`

### 前端入口

- `frontend/src/main.tsx`
  - 通过 `createBrowserRouter(routes)` 启动 React Router。
- `frontend/src/app/router.tsx`
  - 当前主路由：
    - `/` 首页
    - `/patch` CVE Patch 检索
    - `/announcements` 公告工作台
    - `/deliveries` 投递中心
    - `/system/tasks` 任务中心
    - `/system/health` 系统状态

### 后台运行角色

- `backend/app/worker/runtime.py`
  - 统一 Worker 领取并执行 `cve` 与 `announcement` 场景任务。
- `backend/app/scheduler/runtime.py`
  - 当前 scheduler 只负责 heartbeat 和到期投递处理，不是完整调度平台。

## 3. 当前真实三条主链路

### 3.1 平台底座链路

- 首页 API：`backend/app/api/v1/platform/home.py`
- 首页聚合：`backend/app/platform/home_summary.py`
- 健康摘要：`backend/app/platform/health_summary.py`
- 任务运行时：`backend/app/platform/task_runtime.py`
- 首页前端：`frontend/src/routes/HomePage.tsx`

结论：
- 当前平台层不是纯文档或纯壳子，已经有首页、健康、任务、投递这些真实读侧能力。
- 健康摘要按 `api / database / worker / scheduler` 四个维度汇总。

### 3.2 CVE Patch Agent 链路

- 创建 run：
  - `backend/app/api/v1/cve/runs.py::create_run`
  - `backend/app/cve/service.py::create_cve_run`
- Worker 分派：
  - `backend/app/worker/runtime.py::process_once`
- 运行时入口：
  - `backend/app/cve/runtime.py::execute_cve_run`
- 图拓扑：
  - `backend/app/cve/agent_graph.py::build_cve_patch_graph`
- 主要节点：
  - `backend/app/cve/agent_nodes.py`
- 详情聚合：
  - `backend/app/cve/detail_service.py`
- 前端页面：
  - `frontend/src/routes/CVELookupPage.tsx`
  - `frontend/src/routes/CVERunDetailPage.tsx`

结论：
- 当前 CVE 主链已经明确收敛为 `cve_patch_agent_graph`。
- 执行图顺序为：
  - `resolve_seeds`
  - `build_initial_frontier`
  - `fetch_next_batch`
  - `extract_links_and_candidates`
  - `agent_decide`
  - `download_and_validate / finalize_run`
- 运行时由 Playwright 浏览器桥 + LangGraph 组成，不是简单 HTTP 抓取器。

### 3.3 公告提取 / 监控链路

- 手动提取运行时：
  - `backend/app/announcements/runtime.py::execute_announcement_run`
- 监控抓取：
  - `backend/app/announcements/runtime.py::execute_monitor_fetch`
- 监控读侧：
  - `backend/app/api/v1/announcements/monitor_runs.py`
  - `backend/app/announcements/service.py`
- 前端页面：
  - `frontend/src/routes/AnnouncementWorkbenchPage.tsx`
  - `frontend/src/routes/AnnouncementRunDetailPage.tsx`
  - `frontend/src/routes/AnnouncementSourcesPage.tsx`

结论：
- 公告链路不是单次抓取脚本，而是已经接入平台任务系统。
- `announcement_monitor_fetch` 会产出 `SourceFetchRecord`，并为新增内容创建 `announcement_manual_extract` 任务和 `AnnouncementRun`。

## 4. 横切机制

### 统一任务运行时

- Worker 优先领取 `cve`，再领取 `announcement`。
- 不同场景通过 `scene_name + job_type` 分派到具体 runtime。
- 这是当前三条主链路共享的执行底座。

### Heartbeat 与健康观测

- Worker / Scheduler 心跳由 `runtime_heartbeats` 写入。
- 首页和系统状态页依赖 `health_summary` 聚合判断运行角色是否 `healthy / degraded / down`。

### 结果投影与前端工作台

- 平台首页不是直接读单一模型，而是聚合 recent jobs / deliveries / health / scenes。
- CVE 详情页依赖 `detail_service` 聚合 traces、patches、search graph、decision history。

## 5. 当前工作区热点改动

### 5.1 主要热点：CVE 种子与候选证据增强

当前新增或修改文件显示，这一轮开发重点集中在：

- `backend/app/cve/seed_sources.py`
- `backend/app/cve/patch_evidence.py`
- `backend/app/cve/candidate_generator.py`
- `backend/app/cve/decisions/fallback.py`
- `backend/app/cve/agent_search_tools.py`
- 对应测试文件

从代码看，当前正在把“种子源返回普通 URL 列表”增强为“结构化证据 -> 统一证据模型 -> 候选生成”这条链路：

- `seed_sources.py`
  - 新增 `StructuredReference`
  - 新增 `FixCommitEvidence`
  - 新增 `FixedVersionEvidence`
- `patch_evidence.py`
  - 把多个 seed source 归一化为统一 `PatchEvidence`
- `candidate_generator.py`
  - 从 `PatchEvidence` 生成 `PatchCandidate`

这表明当前 CVE 主线正在从“页面探索为主”向“证据优先 + 候选生成更结构化”推进。

### 5.2 fallback 与噪声过滤也在收紧

- `fallback.py`
  - 开始按 role priority 和 URL 归一化做更精细的 frontier fallback 选择。
- `agent_search_tools.py`
  - 新增部分 Red Hat 安全页噪声过滤。

结论：
- 当前热点不是 UI 层，而是 CVE Agent 的导航、候选、证据抽象和真实样本收敛。

## 6. 文档与代码边界

- 当前代码事实可以确认：
  - 平台底座已具备真实 API/Worker/Scheduler/前端路由骨架。
  - CVE 主链是 Playwright + LangGraph 的 `cve_patch_agent_graph`。
  - 公告监控链路已接入统一任务底座。
- 文档作用：
  - `docs/design/*` 和 `docs/04-*` 当前更像结构化导航和实现说明。
  - 结论仍需以实际入口代码为准。

## 7. 首页场景 path 已对齐为 `/patch`

- `backend/app/platform/home_summary.py` 的场景配置（line 20）已使用 `"path": "/patch"`，与前端 `frontend/src/app/router.tsx` 的真实路由 `/patch` 直接对齐。
- 前端 `frontend/src/features/home/presentation.ts::getScenePath()` 对 `scene_name == "cve"` 仍保留映射作为兼容兜底，但已不再承担"修正后端口径"的责任。

结论：
- 已不存在 path 不一致问题；`getScenePath()` 的 scene_name 映射只是历史兼容兜底，可作为后续清理项跟踪。

## 8. 综合判断

当前项目不是泛化的空平台，而是已经具备：

1. 平台底座读侧与最小任务运行时
2. CVE Patch Agent 主链
3. 公告提取 / 监控 / 投递相关链路

当前最活跃、最复杂、风险最高的区域是 `backend/app/cve/*`，尤其是 patch 证据建模、候选生成、frontier fallback 与真实样本收敛。
