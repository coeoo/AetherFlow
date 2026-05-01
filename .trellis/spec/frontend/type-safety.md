# Frontend 类型安全

> TypeScript 配置、类型组织、API 响应契约。

---

## 1. 编译器配置

`frontend/tsconfig.json` 关键项：

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "strict": true,
    "forceConsistentCasingInFileNames": true,
    "isolatedModules": true,
    "module": "ESNext",
    "moduleResolution": "Node",
    "resolveJsonModule": true,
    "noEmit": true,
    "jsx": "react-jsx"
  }
}
```

要点：
- **`strict: true`** 已开启，意味着：strictNullChecks / noImplicitAny / strictFunctionTypes 等全部生效
- **`isolatedModules: true`**：每个文件单独编译，禁止跨文件 const enum 等"全局"特性
- **`forceConsistentCasingInFileNames`**：import 路径大小写必须与文件系统一致
- **没有** `paths` alias —— 当前 import 路径是相对路径（`../components/layout/AppShell`），不要凭空使用 `@/...`

---

## 2. 类型组织

**没有顶层 `frontend/src/types/`**。类型按场景拆到 `features/<scene>/types.ts`：

```
frontend/src/features/home/types.ts        # HomeSummaryPayload, SceneCard, ...
frontend/src/features/cve/types.ts         # CVERunSummary, CVERunDetail, PatchArtifact, ...
frontend/src/features/announcements/types.ts
...
```

---

## 3. 类型与运行时契约

### API 响应

后端真实响应格式（参考 `backend/app/api/v1/cve/runs.py`）：

```ts
type ApiResponse<T> = {
  code: number;
  message: string;
  data: T;
};
```

错误响应（FastAPI HTTPException）：

```ts
type ApiError = {
  detail: string;  // 中文错误描述
};
```

约定：
- 在 `features/<scene>/api.ts` 里把 raw response 解包，把 `data` 字段抽出后返回给 hook，hook 再透传给组件
- 错误状态码（404/422 等）由 `fetch` 的 response.ok 检查抛出，由 react-query 转 `isError`
- 组件只消费 `data` 部分，不再触碰 `code` / `message`

### 运行时校验

**当前不引入** Zod / Yup / io-ts。理由：
- v1 表单数量有限（架构设计 §表单策略）
- 后端 Pydantic 已做请求体校验，前端不必重复
- 减少前端依赖

如未来引入运行时 schema 校验，应在本 spec 显式登记。

---

## 4. 常见模式

### 联合类型

```ts
type CVERunStatus = "pending" | "running" | "succeeded" | "failed";
type HealthLevel = "healthy" | "degraded" | "down";
```

用于：状态字段、工程枚举值。

### 类型守卫

```ts
function isTerminalStatus(status: CVERunStatus): boolean {
  return status === "succeeded" || status === "failed";
}
```

可以放到 `presentation.ts` 与 view model 函数同处。

### 可选字段处理

```ts
const summary = homeSummaryQuery.data;
const sceneCards = summary?.scenes ?? [];   // 默认空数组
const platformName = summary?.platform_name ?? "平台首页";  // 中文默认值
```

**不要**写 `summary!.scenes`（非 null 断言）—— 见禁止段。

---

## 5. 类型与后端契约同步

后端字段名通常是 `snake_case`（`run_id`、`recent_jobs`、`platform_name`）。前端**保持一致**：

```ts
type SceneCard = {
  scene_name: string;
  display_name: string;
  path: string;
};
```

**不要**在前端做 `camelCase` 转换 —— 会在每个 API 边界引入冗余 mapping。

---

## 6. 禁止

- **`any`**：项目 strict 模式下出现 `any` 必须有 `// @ts-expect-error` + 中文注释解释为什么；reviewer 必查
- **类型断言** `as Foo`：除非是从 `unknown` 收紧到具体类型，且有 runtime 守卫保证；不要用 `as any` 绕过编译错
- **非 null 断言** `value!`：除非紧接着的逻辑能保证 value 一定存在（例如 useParams 的路径参数）；优先用 `??` 默认值或显式 `if (!value) return null`
- **隐式 `any`**：strict 模式会报错，但仍要警惕 `function foo(x)` 这类签名
- **声明 `Function` / `Object` 这种过于宽的类型**：用具体函数签名 `(arg: T) => U` 或 `Record<K, V>`
- **凭空创建顶层 `frontend/src/types/`**：当前方案是 features 内自封装，新代码遵循
