# Frontend 状态管理

> 状态分层、TanStack Query 用法、URL 状态、为什么不引入 Redux/Zustand。

---

## 1. 状态四类（来自架构设计 §状态分层）

| 类别 | 由谁承担 | 例子 |
|------|----------|------|
| **服务端状态** | TanStack Query | 场景 run 详情、首页摘要、监控批次列表、投递目标、健康摘要 |
| **URL 状态** | React Router (`useParams` / `useSearchParams`) | runId、tab、搜索条件、筛选 |
| **本地 UI 状态** | 组件 `useState` | 抽屉开关、表单草稿、当前选中 patch、展开的 trace step |
| **全局状态** | **不引入**（v1 明确不用 Redux/Zustand） | — |

---

## 2. 服务端状态：TanStack Query

### 实例配置

`frontend/src/app/query-client.ts`：

```ts
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: false,
      refetchOnWindowFocus: false,
      staleTime: 30_000,
    },
  },
});
```

通过 `frontend/src/app/providers.tsx::AppProviders` 挂到根：

```tsx
<QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
```

### Query Key 规范

**必须**用领域前缀数组：

```ts
["home", "summary"]
["cve", "run", runId]
["cve", "runs", { limit }]
["announcements", "monitor-batch", fetchId]
["deliveries", "records", filters]
["system", "tasks", { limit, statusFilter }]
["system", "health"]
```

**禁止**：
- 单字符串 key：`"home-summary"`
- 拼接字符串：`["cve-run-" + runId]`
- 跨场景共用同一前缀（`["all"]`）

### 缓存失效

Mutation 成功后调用 `queryClient.invalidateQueries`：

```ts
queryClient.invalidateQueries({ queryKey: ["cve"] });          // 刷掉所有 cve 相关
queryClient.invalidateQueries({ queryKey: ["cve", "run"] });   // 只刷掉 run 列表/详情
```

---

## 3. URL 状态

承担：**影响分享 / 回看 / 刷新恢复**的状态。

```tsx
// 路径参数
const { runId } = useParams<{ runId: string }>();

// 搜索参数
const [searchParams, setSearchParams] = useSearchParams();
const tab = searchParams.get("tab") ?? "extract";
```

约束：
- tab 切换、批次筛选、搜索条件 → 进 URL
- 抽屉开关、临时 hover 状态 → **不**进 URL（避免历史污染）

---

## 4. 本地 UI 状态

```tsx
const [drawerOpen, setDrawerOpen] = useState(false);
const [draftCveId, setDraftCveId] = useState("");
```

- 不需要分享或回看 → 用 `useState`
- 表单草稿可以提取到 feature 内的小型 hook（`useCVELookupForm`），但**不要**升到全局

---

## 5. 为什么不引入 Redux / Zustand / Context

来自架构设计 §1.4：

- **服务端状态**已由 TanStack Query 承担（带缓存、轮询、失效）
- **URL 状态**已由 React Router 承担
- **本地 UI 状态**用 `useState` 已足够
- 当前产品主路径是工作台 + 详情页，**没有**复杂跨页面的全局共享业务状态

如果未来真的需要全局状态（例如多场景共用的 toast 队列），应先在架构层评审再写到本 spec。

---

## 6. 派生状态

**不用** `useMemo` 在组件里做复杂派生。改为：

```ts
// presentation.ts 里的纯函数
export function getSceneActionLabel(scene: SceneCard): string { ... }
export function getPlatformHealthItems(health: HealthSummary): HealthItem[] { ... }

// 组件直接调用
const healthItems = healthSummary ? getPlatformHealthItems(healthSummary) : [];
```

好处：可单测、可跨组件复用。

---

## 7. 跨场景数据流

跨场景的数据共用走**后端聚合**（`/api/v1/platform/home`、`/api/v1/platform/health`），不在前端 store 拼装。

例如首页摘要 `useHomeSummary` 一次拿回 `{ scenes, recent_jobs, recent_deliveries, health }`，组件分别消费。

---

## 8. 禁止

- **不要引入 Redux / Zustand / Jotai / Recoil 等全局 store**（v1 明确不需要）
- **不要在 Context 里塞业务数据**（providers.tsx 当前只挂 QueryClientProvider，请保持）
- **不要把 query.data 拷贝到 useState**——会脱离缓存机制
- **不要在组件之间通过 URL hash 私下传值**——hash 仅用于锚点（`#delivery`）
- **不要在 useEffect 里做 fetch**——必须走 query hook
