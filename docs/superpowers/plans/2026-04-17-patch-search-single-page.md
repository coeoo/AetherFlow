# Patch 检索单页结果中心 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 Patch 检索入口改造成 `/patch` 结果优先单页，优先展示历史结果，并保留 `/patch/runs/:runId` 深链详情页。

**Architecture:** 前端保留现有后端 API 和 detail payload，不回滚旧 graph 模型；通过新的页面容器聚合现有结果组件，重写查询状态机与路由层，使 `/patch` 成为主阅读路径，`/patch/runs/:runId` 降级为深链调试页。

**Tech Stack:** React 18、React Router 6、TanStack Query、Vitest、现有 `frontend/src/styles/global.css`

---

### Task 1: 重写路由与 Patch 检索页面状态机

**Files:**
- Modify: `frontend/src/app/router.tsx`
- Modify: `frontend/src/routes/CVELookupPage.tsx`
- Modify: `frontend/src/features/cve/hooks.ts`
- Modify: `frontend/src/features/cve/api.ts`
- Test: `frontend/src/test/router.test.tsx`
- Test: `frontend/src/test/cve-pages.test.tsx`

- [ ] **Step 1: 写失败测试，固定 `/patch` 路由、历史优先与不自动创建 run 的行为**

在 `frontend/src/test/router.test.tsx` 和 `frontend/src/test/cve-pages.test.tsx` 中新增或改写用例，覆盖：

- `/patch` 可进入
- 导航显示 `Patch 检索`
- 输入合法 CVE 后先查历史
- 命中历史时不调用创建 run 接口
- 无历史时显示“可开始检索”的空态

- [ ] **Step 2: 运行测试，确认失败原因是当前仍使用 `/cve` 和旧状态机**

Run: `timeout 60s npm --prefix frontend run test -- --run src/test/router.test.tsx src/test/cve-pages.test.tsx`
Expected: FAIL，断言仍命中 `/cve` 路由和“提交即创建 run”的旧行为。

- [ ] **Step 3: 最小实现 `/patch` 路由、query 参数解析与历史优先状态机**

实现要点：

- `router.tsx` 把主入口从 `/cve` 改成 `/patch`
- `CVELookupPage.tsx` 改为读取 `q` 参数
- 页面先根据 `q` 或用户提交的 CVE 命中最近历史
- 只有点击 `开始检索` / `重新检索` 才创建 run
- `hooks.ts` 新增或扩展“按 CVE 命中历史 run”的辅助逻辑

- [ ] **Step 4: 运行前端测试，确认路由与状态流转绿灯**

Run: `timeout 60s npm --prefix frontend run test -- --run src/test/router.test.tsx src/test/cve-pages.test.tsx`
Expected: PASS

- [ ] **Step 5: 提交当前任务**

```bash
git add frontend/src/app/router.tsx frontend/src/routes/CVELookupPage.tsx frontend/src/features/cve/hooks.ts frontend/src/features/cve/api.ts frontend/src/test/router.test.tsx frontend/src/test/cve-pages.test.tsx
git commit -m "feat: 重构 Patch 检索入口与历史优先状态机"
```

### Task 2: 新建单页结果聚合容器并重绘页面编排

**Files:**
- Create: `frontend/src/features/cve/components/PatchLookupResultPage.tsx`
- Modify: `frontend/src/routes/CVELookupPage.tsx`
- Modify: `frontend/src/features/cve/components/CVEVerdictHero.tsx`
- Modify: `frontend/src/features/cve/components/CVEPatchList.tsx`
- Modify: `frontend/src/features/cve/components/CVETraceTimeline.tsx`
- Modify: `frontend/src/features/cve/components/CVEFixFamilySummary.tsx`
- Modify: `frontend/src/styles/global.css`
- Test: `frontend/src/test/cve-pages.test.tsx`

- [ ] **Step 1: 写失败测试，固定 `/patch` 单页信息层**

在 `frontend/src/test/cve-pages.test.tsx` 中新增或改写用例，覆盖：

- `/patch` 同页显示结果 Hero、主补丁摘要、证据链、开发者详情、最近运行
- 开发者详情默认可见标题、可展开工程区块
- 历史结果与最新结果在同页内切换，不跳详情页

- [ ] **Step 2: 运行测试，确认当前仍是工作台式布局**

Run: `timeout 60s npm --prefix frontend run test -- --run src/test/cve-pages.test.tsx`
Expected: FAIL，当前页面仍以输入区/运行状态/结果摘要/历史四块工作台布局展示。

- [ ] **Step 3: 写最小实现，落地单页聚合容器与结果中心布局**

实现要点：

- 新建 `PatchLookupResultPage.tsx` 作为 `/patch` 主容器
- 复用现有 Verdict / Patch / Trace / FixFamily / Diff 组件
- 把开发者详情回收到 `/patch` 同页底部
- 调整 `global.css`，让页面结构接近旧版高密度单页阅读体验
- 文案统一改为 `Patch 检索`

- [ ] **Step 4: 运行测试，确认单页信息层通过**

Run: `timeout 60s npm --prefix frontend run test -- --run src/test/cve-pages.test.tsx`
Expected: PASS

- [ ] **Step 5: 提交当前任务**

```bash
git add frontend/src/features/cve/components/PatchLookupResultPage.tsx frontend/src/routes/CVELookupPage.tsx frontend/src/features/cve/components/CVEVerdictHero.tsx frontend/src/features/cve/components/CVEPatchList.tsx frontend/src/features/cve/components/CVETraceTimeline.tsx frontend/src/features/cve/components/CVEFixFamilySummary.tsx frontend/src/styles/global.css frontend/src/test/cve-pages.test.tsx
git commit -m "feat: 落地 Patch 检索单页结果中心"
```

### Task 3: 收口详情页命名、回链与局部加载行为

**Files:**
- Modify: `frontend/src/routes/CVERunDetailPage.tsx`
- Modify: `frontend/src/features/cve/components/CVEDiffViewer.tsx`
- Modify: `frontend/src/components/layout/AppShell.tsx`
- Test: `frontend/src/test/cve-pages.test.tsx`
- Test: `frontend/src/test/router.test.tsx`

- [ ] **Step 1: 写失败测试，固定详情页命名与回链**

在测试中覆盖：

- 主导航显示 `Patch 检索`
- 详情页标题与返回按钮收口为 Patch 语义
- 从 `/patch/runs/:runId` 返回 `/patch`
- Diff 加载错误只影响局部区块

- [ ] **Step 2: 运行测试，确认当前详情页仍是 `CVE` 语义**

Run: `timeout 60s npm --prefix frontend run test -- --run src/test/router.test.tsx src/test/cve-pages.test.tsx`
Expected: FAIL，当前标题与回链仍是 `CVE` 命名。

- [ ] **Step 3: 写最小实现，收口详情页文案与壳层命名**

实现要点：

- `AppShell.tsx` 主导航改为 `Patch 检索`
- `CVERunDetailPage.tsx` 改为 `Patch 运行详情`
- 返回按钮统一回 `/patch`
- `CVEDiffViewer.tsx` 保持局部加载与局部错误展示

- [ ] **Step 4: 运行测试，确认详情页与导航收口通过**

Run: `timeout 60s npm --prefix frontend run test -- --run src/test/router.test.tsx src/test/cve-pages.test.tsx`
Expected: PASS

- [ ] **Step 5: 提交当前任务**

```bash
git add frontend/src/routes/CVERunDetailPage.tsx frontend/src/features/cve/components/CVEDiffViewer.tsx frontend/src/components/layout/AppShell.tsx frontend/src/test/cve-pages.test.tsx frontend/src/test/router.test.tsx
git commit -m "feat: 收口 Patch 检索导航与详情页文案"
```

### Task 4: 运行完整前端验证并补齐回归

**Files:**
- Modify: `frontend/src/test/cve-pages.test.tsx`
- Modify: `frontend/src/test/router.test.tsx`

- [ ] **Step 1: 补齐最终回归用例**

补齐以下场景：

- 首页空态
- 无历史空态
- 历史优先展示
- 手动重新检索
- 失败态仍完整展示
- 开发者详情展开
- 历史记录切换当前结果

- [ ] **Step 2: 运行定向测试**

Run: `timeout 60s npm --prefix frontend run test -- --run src/test/cve-pages.test.tsx src/test/router.test.tsx`
Expected: PASS

- [ ] **Step 3: 运行前端完整测试**

Run: `timeout 60s npm --prefix frontend run test -- --run`
Expected: PASS

- [ ] **Step 4: 运行前端构建**

Run: `timeout 60s npm --prefix frontend run build`
Expected: PASS

- [ ] **Step 5: 提交最终回归修正**

```bash
git add frontend/src/test/cve-pages.test.tsx frontend/src/test/router.test.tsx
git commit -m "test: 覆盖 Patch 检索单页结果中心回归"
```
