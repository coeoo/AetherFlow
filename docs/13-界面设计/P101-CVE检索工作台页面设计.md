# P101 CVE 检索工作台页面设计

> **对应模块：M101 CVE 检索工作台**

---

## 🎯 页面目标

`/cve` 是 CVE 场景的主输入页。页面必须让用户在不理解 graph 细节的前提下，完成：

1. 输入或粘贴一个 CVE 编号。
2. 发起或复用一次运行。
3. 在当前页直接看到运行状态与结论摘要。
4. 必要时跳转到详情页继续看证据。

---

## 🚪 入口与出口

### 入口

- 首页点击 `进入 CVE 补丁检索`
- 直接访问 `/cve`

### 出口

- 点击 `查看详情` -> `/cve/runs/{run_id}`
- 顶部导航返回 `/`

---

## 🧱 页面布局

```text
Topbar
  -> Page Hero
  -> Input Panel
  -> Run Status Panel
  -> Verdict Summary Panel
  -> Recent Progress Panel
```

### 区块1：Page Hero

- 标题：`输入 CVE，直接看补丁结论`
- 副标题：强调“先给补丁结论，再给证据页”

### 区块2：输入区

- 单一主输入框：CVE 编号
- 主按钮：`开始检索`
- 辅助提示：合法格式示例

### 区块3：运行状态区

- 当前状态胶囊
- 当前阶段
- 最近进展摘要
- 运行开始时间与耗时

### 区块4：结论摘要区

- 是否找到补丁
- 最可信证据页面
- 是否建议进入详情页
- 主动作：`查看详情`

### 区块5：最近进展区

- 只展示最近 1 到 3 条有效进展
- 不直接展示完整 trace JSON

---

## 🖱️ 关键交互

- 输入非法格式时立即给出前端提示，不发请求。
- `reuse_running=true` 时，同一 CVE 有非终态 run 则附着到已有运行。
- 运行中页面持续轮询，但只刷新状态区与结论摘要区。
- 终态后保留当前结果，不自动清空输入框。

---

## 🎭 状态稿

### 默认态

- 只显示 Hero 与输入区。
- 结果区显示引导文案：`输入一个 CVE 开始检索`。

### 校验失败态

- 输入框下方出现格式提示。
- 提交按钮不可用。

### 创建中/附着中

- 主按钮变为 `检索中...`
- 运行状态区切换为加载态。

### 运行中

- 页面展示当前阶段、最近进展、已运行时长。
- 结论区可显示“尚在检索中”的中间摘要。

### 成功终态

- 结论区展示：
  - 是否找到补丁
  - 主证据链接
  - 查看详情入口

### 失败终态

- 显示失败原因摘要
- 提供重新提交入口
- 不把原始异常堆栈作为主视图

---

## 📦 页面视图对象

### `CVEWorkbenchRunSummary`

| 字段名 | 类型 | 说明 |
|--------|------|------|
| `run_id` | string | 运行 ID |
| `cve_id` | string | CVE 编号 |
| `status` | string | 运行状态 |
| `phase` | string | 当前阶段 |
| `stop_reason` | string | 终止原因 |
| `summary` | object | 结论摘要 |
| `progress` | object | 进度摘要 |

### `CVEWorkbenchPageState`

| 字段名 | 类型 | 说明 |
|--------|------|------|
| `query` | string | 当前输入 |
| `validation_message` | string | 校验提示 |
| `loading` | boolean | 是否正在创建或附着运行 |
| `attach_mode` | string | `latest/requested/null` |
| `active_run` | object | 当前运行摘要 |

---

## 🔌 API 与字段映射

| 页面动作/区块 | API | 主要字段 |
|---------------|-----|----------|
| 创建或复用运行 | `POST /api/v1/cve/runs` | `run_id`、`status`、`phase` |
| 轮询运行摘要 | `GET /api/v1/cve/runs/{run_id}` | `status`、`phase`、`summary`、`progress` |

页面只消费摘要字段。完整证据、patch 与 diff 延迟到 `P102`。

---

## 🪞 参考资产与约束

- 直接继承 `../../../aetherflow.bak/frontend/src/routes/CVELookupPage.tsx` 的页面节奏。
- 直接继承 `../../../aetherflow.bak/frontend/src/components/CVELookupCard.tsx` 的“结论优先”组织方式。
- 不把备份仓里偏开发者细节的字段原样堆在首屏。

---

## 🔄 变更记录

### v1.0 - 2026-04-09
- 新增 CVE 工作台页面规格

---

**文档版本**：v1.0  
**创建日期**：2026-04-09  
**最后更新**：2026-04-09  
**维护人**：AI + 开发团队
