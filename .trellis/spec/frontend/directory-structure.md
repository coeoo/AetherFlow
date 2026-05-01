# Frontend 目录结构

> AetherFlow 前端真实模块组织。AI 子代理写新代码前必须按本文档定位文件。

---

## 1. 当前真实顶层布局

```
frontend/src/
├── app/              # 应用启动壳
│   ├── router.tsx        # RouteObject[] 路由表
│   ├── providers.tsx     # AppProviders（仅 QueryClientProvider）
│   └── query-client.ts   # TanStack Query 全局实例
├── routes/           # 页面级组件（一文件一路由）
├── features/         # 场景内业务模块（按 scene_name 拆分）
│   ├── announcements/
│   ├── cve/
│   ├── deliveries/
│   ├── home/
│   ├── system/
│   └── tasks/
├── components/       # 共享 UI 组件
│   └── layout/           # 当前仅 AppShell.tsx + PlaceholderPage.tsx
├── styles/           # 全局样式
├── test/             # 测试与 setup
│   ├── setup.ts
│   ├── announcement-pages.test.tsx
│   ├── cve-pages.test.tsx
│   ├── platform-pages.test.tsx
│   └── router.test.tsx
└── main.tsx          # bootstrap：挂载 React Router + AppProviders
```

> **代码现状与架构文档差距**：`docs/03-系统架构/前端架构设计.md` "推荐结构"中的顶层 `lib/`、`hooks/`、`types/` 当前**不存在**。项目实际方案是把 API client / hooks / view model / types 收进每个 `features/<scene>/` 内的"四件套"。新代码请按当前方案，不要凭空创建顶层 lib/hooks/types。

---

## 2. Features 四件套模式（关键）

每个 `features/<scene>/` 固定包含：

| 文件 | 职责 | 命名约定 |
|------|------|----------|
| `api.ts` | HTTP 封装：fetch URL、请求体序列化、响应解码 | 函数式导出 |
| `hooks.ts` | TanStack Query hooks：`useXxxQuery` / `useXxxMutation` | 以 `use` 开头 |
| `presentation.ts` | View model 转换：后端 raw 数据 → 页面消费的形态 | 以 `get` 开头：`getScenePath`、`getSceneTitle` |
| `types.ts` | 该场景特有的 TypeScript 类型（API 响应、view model） | `PascalCase` 类型名 |

真实示例：`frontend/src/features/home/{api,hooks,presentation,types}.ts`、`frontend/src/features/cve/{api,hooks,presentation,types}.ts`

部分 feature 还有 `components/` 子目录（如 `features/cve/components/`），承载该场景特有的领域组件。

---

## 3. 路由

入口：`frontend/src/app/router.tsx`

主路由清单（与后端 `home_summary` 对齐）：

| Path | Component | 备注 |
|------|-----------|------|
| `/` | `HomePage` | 平台首页摘要 |
| `/patch` | `CVELookupPage` | CVE Patch 工作台（**不是 `/cve`**） |
| `/patch/runs/:runId` | `CVERunDetailPage` | CVE 运行详情 |
| `/announcements` | `AnnouncementWorkbenchPage` | 公告手动提取 + 监控 tab |
| `/announcements/sources` | `AnnouncementSourcesPage` | 监控源管理 |
| `/announcements/runs/:runId` | `AnnouncementRunDetailPage` | 公告运行详情 |
| `/deliveries` | `DeliveryCenterPage` | 投递中心 |
| `/system/tasks` | `TaskCenterPage` | 任务中心 |
| `/system/health` | `SystemHealthPage` | 系统状态 |

约束（来自 `docs/03-系统架构/前端架构设计.md`）：
- 一级导航：首页、Patch 检索、安全公告
- 工具导航：投递中心、系统
- `/cve` **不允许**作为当前实现路径，仅可在历史文档中作为产品语义

---

## 4. 命名约定

- **文件**：组件 `PascalCase.tsx`，工具 `camelCase.ts`
- **组件**：`PascalCase`，与文件名一致（`HomePage` ↔ `HomePage.tsx`）
- **Hooks**：以 `use` 开头（`useHomeSummary`、`useCVERunDetail`）
- **View model 函数**：以 `get` / `derive` 等动词开头（`getScenePath`、`getSceneActionLabel`）
- **类型**：`PascalCase`（`HomeSummaryPayload`、`SceneCard`）
- **测试文件**：放 `frontend/src/test/`，按页面类别分组（`<scene>-pages.test.tsx`）

---

## 5. 禁止

- **不要凭空创建顶层 `lib/`、`hooks/`、`types/`** —— 当前方案是 features 内自封装
- **不要在页面 `routes/*.tsx` 内直接 `fetch()`** —— 必须走 `features/<scene>/api.ts` + `hooks.ts`
- **不要在不同 features 之间互相 import** —— 跨场景共享走 `components/` 或专门的 `features/<scene>/presentation.ts` 显式导出
- **不要把场景语义组件写进 `components/layout/`** —— 那里只放 AppShell 等通用容器
- **不要新建 `/cve` 路由** —— 当前真相是 `/patch`
