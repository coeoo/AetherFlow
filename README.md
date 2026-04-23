# AetherFlow

AetherFlow 是一个面向安全情报处理的智能体平台。
平台以统一任务执行、文档采集、图运行时、证据留存与结果投递为共用底座，
承载两个首批业务场景：

- `CVE Patch Agent`：输入 CVE 编号，执行多源 seed 聚合、受控多跳页面探索、
  patch 收敛、下载校验与证据回放。
- `安全公告提取`：输入或持续监控公告源，抽取结构化情报并输出可投递结果。

## 产品主线

- `Patch Agent` 是当前产品主叙事。
- `LangGraph` 负责编排 Patch 搜索中的状态流转、循环决策、预算控制与收敛。
- 规则库不再承担主搜索策略，而是作为页面角色识别、候选校验、风险约束和
  模型护栏存在。
- 详情页必须能回放搜索图、frontier、预算、决策历史、patch 收敛与 diff。

## 目录概览

- `backend/`：FastAPI、Worker、Scheduler、SQLAlchemy 模型与后端测试。
- `frontend/`：Vite + React 页面、路由与前端测试。
- `infra/`：本地开发 PostgreSQL 相关容器配置。
- `scripts/`：环境引导、验证脚本与开发辅助命令。
- `docs/`：总设计、架构、功能设计、界面设计与 AI 开发日志。

## 本地准备

建议准备以下环境：

- Python 3.11
- Node.js 20+ 与 npm
- Docker / Docker Compose
- 可选：`uv`，用于更快地创建 Python 虚拟环境

安装依赖：

```bash
make backend-install frontend-install
```

## 本地模型配置

浏览器 Agent 的真实验收默认从仓库根目录的 `.env.local` 读取 OpenAI 兼容模型配置。
该文件已被 Git 忽略，适合存放本机私有配置，不会进入版本控制。

建议在仓库根目录维护：

```env
LLM_BASE_URL=<YOUR_OPENAI_COMPATIBLE_BASE_URL>
LLM_API_KEY=<YOUR_API_KEY>
LLM_DEFAULT_MODEL=<YOUR_MODEL_NAME>
```

运行时如果显式设置了同名环境变量，会覆盖 `.env.local` 中的值。

## 关键验证命令

Phase 0 规范与 SQL 初始化顺序验证：

```bash
timeout 60s bash scripts/verify_phase0_spec_consistency.sh

AETHERFLOW_PHASE0_PG_CONTAINER=aetherflow-phase0-pg-alt \
AETHERFLOW_PHASE0_PG_PORT=55433 \
timeout 60s bash scripts/verify_sql_init_order.sh
```

统一工程验证：

```bash
timeout 60s make phase1-verify
```

## 最小运行入口

启动本地 PostgreSQL：

```bash
docker compose -f infra/docker-compose.dev.yml up -d postgres
```

启动后端 API：

```bash
timeout 60s ./.venv/bin/python -m uvicorn app.main:app \
  --app-dir backend \
  --host 0.0.0.0 \
  --port 18080
```

健康检查：

```bash
curl -sS http://127.0.0.1:18080/api/v1/platform/health
curl -sS http://127.0.0.1:18080/api/v1/platform/home-summary
```

启动前端开发服务器：

```bash
npm --prefix frontend run dev -- --host 0.0.0.0 --port 5180
```

前端主要入口：

- `/`：平台首页，展示场景入口、最近任务、最近投递与系统状态摘要
- `/cve`：CVE Patch 搜索工作台
- `/cve/runs/{run_id}`：Patch 搜索详情页，查看搜索图、预算、patch 收敛与 diff
- `/announcements`：安全公告提取工作台
- `/announcements?tab=monitoring`：公告监控批次与关联 run 详情
- `/deliveries`：投递中心
- `/deliveries?tab=records`：投递记录、立即发送、计划发送、失败重试
- `/system/health`：系统状态页
- `/system/tasks`：任务中心

## 浏览器 Agent 真实验收

当前仓库已经在真实 DashScope OpenAI 兼容配置下完成两条浏览器 Agent 验收：

- `CVE-2022-2509`：`mailing_list_page -> tracker_page -> commit_page -> patch download`
- `CVE-2024-3094`：多链路跨域场景，可直接从 `oss-security` 收敛到上游 commit patch

推荐的本地验收命令：

```bash
cd backend

DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev \
AETHERFLOW_CVE_RUNTIME_DIAGNOSTIC_MODE=true \
python -m scripts.acceptance_browser_agent \
  --cve CVE-2022-2509 \
  --llm-wall-clock-timeout-seconds 90 \
  --diagnostic-timeout-seconds 360 \
  --max-llm-calls 4 \
  --max-pages-total 12 \
  --results-dir results/live-acceptance-cve-2022-2509
```

```bash
cd backend

DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev \
AETHERFLOW_CVE_RUNTIME_DIAGNOSTIC_MODE=true \
python -m scripts.acceptance_browser_agent \
  --cve CVE-2024-3094 \
  --llm-wall-clock-timeout-seconds 90 \
  --diagnostic-timeout-seconds 360 \
  --max-llm-calls 6 \
  --max-pages-total 16 \
  --results-dir results/live-acceptance-cve-2024-3094
```

验收报告会输出到 `backend/results/<run-name>/acceptance_report.json` 与
`backend/results/<run-name>/llm_decisions_log.jsonl`。

## 文档阅读入口

- `docs/00-总设计/总体项目设计.md`：仓库总纲与统一目标
- `docs/03-系统架构/架构设计.md`：运行拓扑、分层与主链边界
- `docs/04-功能设计/README.md`：模块索引与开发顺序
- `docs/13-界面设计/README.md`：页面级 UI 规格与信息架构
- `docs/04-功能设计/M103-CVE数据源与页面探索规则功能设计.md`：
  CVE 浏览器 Agent 主链与页面探索规则
- `docs/superpowers/specs/2026-04-21-cve-browser-agent-design.md`：
  浏览器 Agent 重设计规格（阶段性设计记录）
- `docs/09-AI开发日志/README_AI使用说明.md`：AI 会话接手说明与日志规范
