# Frontend Hook 约定

> Hook 命名、TanStack Query 模式、轮询策略。

---

## 1. Hook 位置

当前项目**没有**顶层 `frontend/src/hooks/` 目录。Hook 按场景写在：

```
frontend/src/features/<scene>/hooks.ts
```

例如：
- `frontend/src/features/home/hooks.ts::useHomeSummary`
- `frontend/src/features/cve/hooks.ts::useCVERunDetail` 等

**不要**新建 `frontend/src/hooks/`——按当前方案保持收口在 features 内。

---

## 2. 命名约定

- **必须以 `use` 开头**（React 强制，linter 也会检查）
- 后跟领域名 + 动作：
  - `useHomeSummary` — 拉取首页摘要
  - `useCVERunDetail` — 拉取单个 CVE 运行详情
  - `useDeliveryRecords` — 拉取投递记录列表
  - `useTriggerCVERun` — mutation：触发新 CVE run
- Mutation 用 `useTriggerXxx` / `useUpdateXxx` / `useRetryXxx`，不用 `useXxxMutation`

---

## 3. TanStack Query 模式

### Query

```ts
import { useQuery } from "@tanstack/react-query";
import { fetchHomeSummary } from "./api";

export function useHomeSummary() {
  return useQuery({
    queryKey: ["home", "summary"],
    queryFn: fetchHomeSummary,
  });
}
```

要点：
- **queryKey 必须用领域前缀**（架构设计 §状态分层 §1）：
  - `["home", "summary"]`
  - `["cve", "run", runId]`
  - `["announcements", "monitor-batch", fetchId]`
  - `["deliveries", "records", filters]`
- **queryFn 调用 `./api.ts` 里的纯函数**，hook 不直接 fetch
- 全局默认（来自 `frontend/src/app/query-client.ts`）：
  - `retry: false`（失败不自动重试）
  - `refetchOnWindowFocus: false`
  - `staleTime: 30_000`（30 秒内不重新请求）

### Mutation

```ts
import { useMutation, useQueryClient } from "@tanstack/react-query";

export function useTriggerCVERun() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: triggerCVERun,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["cve"] });
    },
  });
}
```

约定：
- 成功后 `invalidateQueries` 触发相关 query 重拉
- 错误处理由调用方在 `mutation.error` 或 `onError` 回调中决定 UI 反馈

---

## 4. 轮询策略

来自架构设计 §轮询与实时策略：

| 场景 | 间隔 | 停止条件 |
|------|------|----------|
| CVE 工作台（active run） | 1~2 秒 | 进入终态 |
| CVE 工作台（终态后） | 终态后额外刷新最近运行列表一次（保证摘要与历史一致） | — |
| 公告手动提取 | 1~2 秒 | 进入终态 |
| 监控批次详情 | 试跑后短轮询 | 终态后停止 |
| 首页摘要 / 系统健康 | 低频或手动 | — |

实现模式：

```ts
export function useCVERunDetail(runId: string) {
  return useQuery({
    queryKey: ["cve", "run", runId],
    queryFn: () => fetchCVERun(runId),
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      if (!status || isTerminalStatus(status)) return false;
      return 1500;
    },
  });
}
```

**不要**把轮询定时器写进组件 useEffect。

---

## 5. URL 状态与 hook 协作

URL 参数由 `useParams` / `useSearchParams` 提供，hook 接收后透传到 queryKey：

```ts
import { useParams } from "react-router-dom";

export function CVERunDetailPage() {
  const { runId } = useParams<{ runId: string }>();
  const detailQuery = useCVERunDetail(runId!);
  // ...
}
```

URL 状态承载（架构设计 §状态分层 §2）：搜索条件、tab 切换、当前批次/筛选。

---

## 6. 派生状态

把 query.data 派生为 view model 用 **presentation.ts 函数**，不在 hook 内 useMemo：

```ts
// 反例：hook 内做转换 ❌
export function useHomeSceneCards() {
  const summary = useHomeSummary();
  return useMemo(() => summary.data?.scenes.map(toCard), [summary.data]);
}

// 正例：hook 只拿数据，组件层调用 presentation ✅
const summaryQuery = useHomeSummary();
const sceneCards = (summaryQuery.data?.scenes ?? []).map(getSceneActionLabel);
```

理由：presentation 函数可单测，可在多组件共享。

---

## 7. 禁止

- **不要在页面 useEffect 里手动 fetch + setState**——必须用 query/mutation
- **不要把 queryKey 字符串拼接** （`['home-summary']`）——用数组 `["home", "summary"]`
- **不要忽略 hook 返回的 `isLoading` / `isError`**——组件必须四态齐全（参见 component-guidelines）
- **不要 hardcode 轮询间隔在组件里**——写在 hook 的 `refetchInterval` 函数中
- **不要让 hook 同时承担转换职责**——拆给 presentation
