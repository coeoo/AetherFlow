# AetherFlow

AetherFlow 是一个面向安全情报处理的承载平台与场景工作台仓库。
当前仓库已经完成 Phase 0 规范收口、Phase 1 工程骨架与 Phase 2 平台底座，
并落地了 CVE patch fast-first 最小垂直切片，具备可验证的后端 API、Worker
执行链、前端工作台/详情页、PostgreSQL/Alembic 测试基础与统一验证入口。

## 当前状态

- 已完成：文档先行、数据库分层与 FK 收口、运行拓扑统一、平台任务/Artifact/
  心跳底座、CVE patch fast-first 最小主链、平台首页真实摘要、系统状态页真实健
  康摘要、任务中心真实列表、安全公告工作台手动提取、公告监控批次查询与详情、
  投递中心目标管理与投递记录执行动作、统一验证命令与健康检查入口。
- 部分完成：scheduler 已承担 heartbeat 与监控批次相关职责，安全公告场景已具备
  手动提取与监控结果查询切片，但“完整自动调度语义”和“更多来源适配闭环”仍需
  继续收口。
- 未完成：更完整的安全公告自动调度策略、更多渠道适配细节、平台级更深的运维治理
  与更复杂的权限/租户能力。
- 当前可验证的是“平台底座 + CVE 主链 + 公告监控/投递执行最小闭环可运行”，不
  是“所有长期规划能力都已经完成”。

## 目录概览

- `backend/`：FastAPI、Alembic、SQLAlchemy 模型、运行入口与后端测试。
- `frontend/`：Vite + React 路由壳、页面占位模块与前端测试。
- `infra/`：本地开发 PostgreSQL 相关容器配置。
- `scripts/`：环境引导、Phase 0 规范一致性与 SQL 初始化顺序验证脚本。
- `docs/`：总体设计、功能设计、页面设计、部署运维与 AI 开发日志。

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

## 关键验证命令

Phase 0 规范与 SQL 顺序验证：

```bash
timeout 60s bash scripts/verify_phase0_spec_consistency.sh

AETHERFLOW_PHASE0_PG_CONTAINER=aetherflow-phase0-pg-alt \
AETHERFLOW_PHASE0_PG_PORT=55433 \
timeout 60s bash scripts/verify_sql_init_order.sh
```

Phase 1 工程骨架统一验证：

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

当前前端可直接验证的入口：

- `/`：平台首页，展示场景入口、最近任务、最近投递与系统状态摘要
- `/cve`：CVE 工作台
- `/announcements`：安全公告手动提取工作台
- `/announcements?tab=monitoring`：公告监控批次与关联 run 详情
- `/deliveries`：投递目标管理
- `/deliveries?tab=records`：投递记录、立即发送、计划发送、失败重试
- `/system/health`：系统状态页
- `/system/tasks`：任务中心

## 参考文档

- `docs/00-总设计/总体项目设计.md`：仓库总纲与当前项目约束
- `docs/03-系统架构/架构设计.md`：运行拓扑与工程分层
- `docs/04-功能设计/README.md`：模块设计索引与实现顺序
- `docs/09-AI开发日志/README_AI使用说明.md`：AI 会话接手说明与日志规范
