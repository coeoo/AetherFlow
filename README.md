# AetherFlow

AetherFlow 是一个面向安全情报处理的承载平台与场景工作台仓库。
当前仓库已经完成 Phase 0 规范收口与 Phase 1 工程骨架，具备最小后端 API、
前端路由壳、PostgreSQL/Alembic 测试基础与统一验证入口。

## 当前状态

- 已完成：文档先行、数据库分层与 FK 收口、运行拓扑统一、后端基础工程、
  前端路由壳、统一验证命令与健康检查入口。
- 未完成：CVE 业务主链、安全公告正文与 URL 处理链、监控调度完整语义、
  投递业务闭环。
- 当前可验证的是“平台工程骨架可运行”，不是“业务场景已经闭环”。

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
  --host 127.0.0.1 \
  --port 18080
```

健康检查：

```bash
curl -sS http://127.0.0.1:18080/api/v1/platform/health
```

启动前端开发服务器：

```bash
npm --prefix frontend run dev
```

## 参考文档

- `docs/00-总设计/总体项目设计.md`：仓库总纲与当前项目约束
- `docs/03-系统架构/架构设计.md`：运行拓扑与工程分层
- `docs/04-功能设计/README.md`：模块设计索引与实现顺序
- `docs/09-AI开发日志/README_AI使用说明.md`：AI 会话接手说明与日志规范
