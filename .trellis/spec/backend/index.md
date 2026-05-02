# Backend Development Guidelines

> AetherFlow 后端开发约定。所有 trellis-implement / trellis-check 子代理写后端代码前必读。

---

## Overview

本目录承载 AetherFlow 后端开发的真实规范。来源：

- 仓库级协作约束（`AGENTS.md`）
- 项目代码规范（`docs/06-开发规范/代码规范.md`、`Git规范.md`）
- 系统架构（`docs/03-系统架构/架构设计.md`、`数据库设计.md`）
- 实现设计（`docs/design/*.md`）
- 真实代码模式（`backend/app/`、`backend/tests/`）

---

## Guidelines Index

| Guide | 描述 | 状态 |
|-------|------|------|
| [Directory Structure](./directory-structure.md) | 顶层布局、模块边界、命名约定 | Filled |
| [Database Guidelines](./database-guidelines.md) | SQLAlchemy + Alembic + PostgreSQL + 测试 DB | Filled |
| [Error Handling](./error-handling.md) | API 响应格式 `{code, message, data}` + HTTPException + 长任务 stop_reason | Filled |
| [Quality Guidelines](./quality-guidelines.md) | 测试规模 / 运行产物边界 / 敏感配置 / 提交质量 | Filled |
| [Logging Guidelines](./logging-guidelines.md) | stdlib logging + `[CVE:%s]` 前缀 + `%s` 占位符 | Filled |
| [CVE Conventions](./cve-conventions.md) | CVE 场景层非显然约定（acceptance 真实网络边界 / canonical_key 与 normalize 关系） | Filled |

---

## How to Use These Guidelines

每个 guideline 文件都按"AI 子代理需要的最小决策依据"裁剪，特点：

1. **写真实，不写理想**——文档反映当前 `backend/app/` 实际行为，不是规划目标
2. **禁止段落写真坑**——每个文件的 "禁止" 都来自代码 review 中真实出现过的反模式
3. **引用真实路径**——所有示例都给 `backend/app/...` / `backend/tests/...` 形式可点击路径
4. **诚实标注差距**——例如 logging 部分明示"未引入结构化日志框架"，避免子代理凭空写 structlog

---

## 关联文档

- 长期实现细节 → `docs/design/<topic>.md`（不在本 spec 重复展开）
- 协作规则、阶段事实、入口索引 → `AGENTS.md`
- 工作流与任务流转 → `.trellis/workflow.md`
- 通用思维守则 → `.trellis/spec/guides/`

---

**Language**: 全部使用简体中文（与项目语言一致）。
