# Frontend 组件约定

> 组件分层、props 模式、样式策略、可访问性。

---

## 1. 组件三层（来自架构设计 §组件分层）

| 层 | 位置 | 职责 | 禁止 |
|---|---|---|---|
| **页面编排** | `frontend/src/routes/*.tsx` | 组合 Hero / 表单 / 结果 / 详情；绑定 URL 状态与页面级动作；处理页面降级与错误边界 | 不直接发 HTTP；不写复杂数据转换（交给 `features/<scene>/presentation.ts`） |
| **领域特征** | `frontend/src/features/<scene>/components/*` 或同目录下 .tsx | 依赖场景 view model 的领域组件，例如 CVE 结论卡、公告情报包摘要 | 不承担路由职责；不持有顶层布局 |
| **原子与共享** | `frontend/src/components/layout/*` | 通用 UI（壳、空态、错误态） | 不依赖具体场景字段名；只接收通用 props |

当前 `components/layout/` 仅有 `AppShell.tsx`、`PlaceholderPage.tsx`，组件库尚轻。

---

## 2. 标准组件结构

参考 `frontend/src/routes/HomePage.tsx`：

```tsx
import { Link } from "react-router-dom";

import { AppShell } from "../components/layout/AppShell";
import { useHomeSummary } from "../features/home/hooks";
import {
  getRecentJobTitle,
  getSceneActionLabel,
  getScenePath,
  getSceneTitle,
} from "../features/home/presentation";

export function HomePage() {
  const homeSummaryQuery = useHomeSummary();
  const summary = homeSummaryQuery.data;
  // ...衍生数据全部来自 presentation 转换
  return (
    <AppShell eyebrow="平台首页" title={...} description={...} actions={...}>
      {/* 区块 */}
    </AppShell>
  );
}
```

要点：
- **export named function** `export function HomePage()`，不要 default export
- **顶部用 hooks 拿数据**，再交给 presentation 转换
- **JSX 直接消费 view model**，不要在 JSX 里写复杂 `?:` 嵌套或 `.filter().map()` 链
- **页面外层包 `<AppShell>`**：统一 eyebrow / title / description / actions

---

## 3. Props 约定

- **必须用 TypeScript 类型/interface**，不允许 `any`
- 简单组件直接内联类型：

  ```tsx
  export function StatusPill({ level, label }: { level: "healthy" | "degraded" | "down"; label: string }) { ... }
  ```

- 复杂 props 用专门 type：

  ```tsx
  type SceneCardProps = {
    scene: SceneCard;
    onSelect?: (sceneName: string) => void;
  };
  ```

- 事件回调用 `on` + 动词：`onSubmit` / `onSelect` / `onRetry`
- 可选 props 用 `?:`，不要默认 `undefined`
- **不要传整个 query 对象给子组件**——传 view model 数据 + 状态 flag

---

## 4. 样式策略

- 当前样式集中在 `frontend/src/styles/`（CSS）和 className 字符串中
- **未引入** styled-components / emotion / Tailwind / CSS Modules
- 类名约定：`<region>-<element>-<variant>`，例如 `summary-card`、`summary-card-emphasis`、`status-pill-healthy`
- 状态用类名后缀传达：`status-pill-{healthy|degraded|down}`

> 如未来引入 CSS-in-JS 方案，应先评估再写到本 spec。

---

## 5. 可访问性（最低线）

来自架构设计 §响应式与可访问性：

- **表单控件必须有 label**
- **状态颜色不能作为唯一信息来源**（必须有文字 label）
- **关键动作按钮必须有明确文本**，不只用图标
- 区块用 `<section aria-label="...">` 或 `<article>` 标识语义

示例（HomePage.tsx）：
```tsx
<section className="dashboard-stat-grid" aria-label="平台首页摘要">
```

---

## 6. 状态展示（必须四态齐全）

每个数据驱动的页面/区块都要处理：

| 态 | 何时出现 | 表现 |
|---|---|---|
| **loading** | query.isLoading | 占位骨架或 "loading" 文本 |
| **empty** | data 已返回但 list/数量为 0 | 友好空态 + 可选行动指引 |
| **error** | query.isError | 错误提示 + 重试按钮（必要时） |
| **success/ready** | data 可用 | 渲染真实内容 |

参考 HomePage.tsx 的 `homeSummaryQuery.isLoading ? "loading" : healthLevel`。

---

## 7. 禁止

- **不要 default export 组件**（统一 named export，便于 grep 与重构）
- **不要在 props 里塞 `style={{}}` 行内样式**（除非是真正动态计算的 inline，例如 width 百分比）
- **不要在组件里直接写中文硬编码 + 渲染原始后端字段名**（例如 `{run.stop_reason}`）——必须经过 presentation 翻译为人类可读 label
- **不要在路由组件里写复杂业务逻辑**——抽到 `features/<scene>/presentation.ts` 或 hook
- **不要忽略 loading/empty/error 任一状态**——会让用户卡在白屏或看到 undefined
