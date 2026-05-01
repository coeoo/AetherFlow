# Frontend 质量约定

> 测试方案、构建命令、提交质量、Code Review 关注点。

---

## 1. 测试栈

来自 `frontend/package.json`：

| 工具 | 版本 | 用途 |
|------|------|------|
| **vitest** | ^2.1.5 | 测试运行器（jsdom 环境） |
| **@testing-library/react** | ^16.0.1 | 组件渲染断言 |
| **@testing-library/jest-dom** | ^6.6.3 | DOM matcher 扩展 |
| **jsdom** | ^25.0.1 | 浏览器环境模拟 |

配置：`frontend/vitest.config.ts`

```ts
export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: "./src/test/setup.ts",
  },
});
```

**未引入**：jest、cypress、playwright（前端层面 e2e）。后端 `backend/tests/test_acceptance_browser_agent.py` 用 Playwright 做的是 backend Agent 测试，与前端测试栈无关。

---

## 2. 测试位置

```
frontend/src/test/
├── setup.ts                       # @testing-library/jest-dom 初始化等
├── announcement-pages.test.tsx
├── cve-pages.test.tsx
├── platform-pages.test.tsx
└── router.test.tsx
```

按页面**类别**拆分（不是一文件一组件）。新增场景应该新增 `<scene>-pages.test.tsx`，而不是把测试散落到 `routes/`、`features/` 各处。

---

## 3. 必须覆盖的测试集合

来自架构设计 §前端测试与验收：

### 路由级 smoke

```
/、/patch、/announcements、/deliveries、/system/tasks
```

每条路由能渲染出 AppShell，不抛 React error。参考 `frontend/src/test/router.test.tsx`。

### 页面状态

每个数据驱动的页面必须覆盖：
- **加载态**（loading）
- **空态**（empty）
- **错误态**（error）
- **终态**（ready/success）

### 关键交互

- CVE 输入校验（`^CVE-\d{4}-\d{4,}$`）
- 公告双模式切换（手动 / 监控）
- 监控源试跑
- 投递目标测试发送
- 任务重试

---

## 4. 测试命令

来自 `frontend/package.json` + `Makefile`：

```bash
# 仓库根目录
make frontend-test    # timeout 60s npm --prefix frontend test -- --run

# frontend/ 内
npm test              # 交互模式（watch）
npm test -- --run     # 一次性跑完
```

约定：
- CI / 主线程验证一律用 `make frontend-test`（带 60 秒超时）
- watch 模式只在本地开发用

---

## 5. 构建与开发

```bash
make frontend-install   # timeout 60s npm install
npm --prefix frontend run dev    # vite dev server
npm --prefix frontend run build  # 生产构建
```

`phase1-verify` 会跑 `frontend test + build`（参考 Makefile）。

---

## 6. Lint / 格式化

**当前无 ESLint 配置**（`frontend/` 下没有 `.eslintrc*` 或 `eslint.config.*`）。
**当前无 Prettier 配置**。

实际质量约束依赖：
- TypeScript strict 模式（编译期捕获 any / undefined / 未定义变量）
- Code review 人工把关
- 本 spec 中的 "禁止" 段

如果未来引入 ESLint，应先评审规则集（推荐 `@typescript-eslint/recommended` + `react-hooks/recommended`），并更新本 spec。

---

## 7. 提交质量

承袭后端约定（参见 `.trellis/spec/backend/quality-guidelines.md` §5 + `AGENTS.md` §3.1）：

- 提交信息**必须使用简体中文**
- 标题禁止 `fix bug` / `update`
- 正文说明：改了什么 / 为什么 / 验证了什么（最少跑了 `make frontend-test`）

---

## 8. Code Review 关注点

资深 reviewer 视角对前端改动：

1. **状态四态齐全**：loading / empty / error / ready 全覆盖（component-guidelines §6）
2. **没有 `any` / 非 null 断言不带说明**（type-safety §6）
3. **没有页面里直接 fetch**（hook-guidelines §1）
4. **没有 default export 组件**（component-guidelines §7）
5. **queryKey 用领域前缀数组**（state-management §2）
6. **路由不混入 `/cve`**（directory-structure §3）
7. **没有引入 Redux / Zustand**（state-management §5）
8. **跨 features 之间没有隐式依赖**（directory-structure §5）
9. **后端字段名保持 snake_case**（type-safety §5）

---

## 9. 禁止

- **不要把测试文件散落到 routes/ 或 features/ 里**——统一收到 `frontend/src/test/`
- **不要 watch 模式跑 CI**（`make frontend-test` 已经带 `--run`）
- **不要在 build 阶段静默忽略类型错误**——`tsc --noEmit` 应作为构建闸门
- **不要新建未列入 spec 的依赖**（如 lodash / day.js / framer-motion 等）——优先评审是否真有必要
- **不要绕过 `make` 命令直接跑 `npm install` / `npm test`**——容易丢超时和环境一致性
