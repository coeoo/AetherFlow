# Frontend Development Guidelines

> AetherFlow 前端开发约定。所有 trellis-implement / trellis-check 子代理写前端代码前必读。

---

## Overview

本目录承载 AetherFlow 前端开发的真实规范。来源：

- 仓库级协作约束（`AGENTS.md`）
- 系统架构（`docs/03-系统架构/前端架构设计.md`、`docs/03-系统架构/架构设计.md`）
- 真实代码模式（`frontend/src/` 全量探索）
- 当前依赖：`frontend/package.json`

**关键事实**：前端栈是 React 18 + TypeScript 5 + Vite 6 + React Router 6 + TanStack Query 5 + vitest 2，**未引入** ESLint / Prettier / Zustand / Redux / 任何 CSS-in-JS 框架。

---

## Guidelines Index

| Guide | 描述 | 状态 |
|-------|------|------|
| [Directory Structure](./directory-structure.md) | 真实目录布局 + features 四件套（api/hooks/presentation/types） | Filled |
| [Component Guidelines](./component-guidelines.md) | 三层组件 + named export + 四态齐全 | Filled |
| [Hook Guidelines](./hook-guidelines.md) | TanStack Query 模式 + queryKey 数组 + 轮询写在 refetchInterval | Filled |
| [State Management](./state-management.md) | 服务端/URL/UI 三类 + 不引入 Redux/Zustand | Filled |
| [Type Safety](./type-safety.md) | strict 模式 + 后端字段保持 snake_case + 禁 any/!断言 | Filled |
| [Quality Guidelines](./quality-guidelines.md) | vitest + 路由 smoke + 状态四态测试 + 中文提交 | Filled |

---

## How to Use These Guidelines

每个 guideline 都按"AI 子代理需要的最小决策依据"裁剪：

1. **写真实，不写理想**——文档反映当前 `frontend/src/` 实际行为；架构文档"推荐"但代码未实现的部分（如顶层 `lib/` / `hooks/` / `types/`）显式标注差距
2. **禁止段落写真坑**——例如禁止 `/cve` 新路由、禁止 default export、禁止 useEffect 内 fetch
3. **引用真实路径**——所有示例给 `frontend/src/...` 形式可点击路径
4. **诚实标注缺位**——例如 type-safety 明示"当前不引入 Zod / Yup"，避免子代理凭空写 schema 校验

---

## 关联文档

- 长期实现细节 → `docs/03-系统架构/前端架构设计.md`（不在本 spec 重复展开）
- 协作规则、阶段事实 → `AGENTS.md`
- 工作流与任务流转 → `.trellis/workflow.md`
- 通用思维守则 → `.trellis/spec/guides/`
- 后端 spec → `.trellis/spec/backend/`（保持前后端契约一致）

---

**Language**: 全部使用简体中文（与项目语言一致）。
