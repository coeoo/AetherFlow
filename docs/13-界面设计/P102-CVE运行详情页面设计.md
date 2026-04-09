# P102 CVE 运行详情页面设计

> **对应模块：M102 CVE 运行详情与补丁证据**

---

## 🎯 页面目标

`/cve/runs/{run_id}` 是 CVE 场景的证据页，负责把一次 graph run 的结论、证据链、fix family、patch 与 diff 组织为可复核页面。

它必须优先回答：

1. 是否找到可信补丁。
2. 为什么认为它可信。
3. 如果用户要复核，应从哪里看起。

---

## 🚪 入口与出口

### 入口

- `P101` 点击 `查看详情`
- 首页最近任务跳转
- 直接访问 `/cve/runs/{run_id}`

### 出口

- 返回 `/cve`
- 打开外部证据页
- 打开 patch diff 查看区

---

## 🧱 页面布局

```text
Topbar
  -> Verdict Hero
  -> Primary Patch Summary
  -> Fix Family List
  -> Patch List
  -> Trace Timeline
  -> Diff Viewer
```

### 区块1：Verdict Hero

- 状态胶囊
- CVE 编号
- 主结论标题
- 可信原因
- 下一步建议
- 主动作：查看主补丁、查看证据页面、查看主补丁 diff

### 区块2：主补丁摘要

- 推荐补丁
- 下载状态
- 证据入口
- 影响产品

### 区块3：Fix Family

- 展示 family 列表与主 family 标识
- 每个 family 显示归并原因、候选数、主要证据

### 区块4：Patch 列表

- 展示候选补丁、来源、下载状态、大小、类型
- 可展开 patch 元信息

### 区块5：Trace 时间线

- 以可读时间线展示页面探索过程
- 每步包含来源、命中原因、下一跳关系

### 区块6：Diff Viewer

- 独立大文本阅读区
- 只有用户点击查看时才加载

---

## 🖱️ 关键交互

- 页面首屏默认显示 Verdict Hero，不需要滚动就能读到主结论。
- `查看主补丁 diff` 是页内展开动作，不跳新页面。
- Trace 支持逐步展开，但默认只展示摘要标题和命中原因。
- Patch 列表与 Trace 时间线视觉上必须分层，避免信息混杂。

---

## 🎭 状态稿

### 加载态

- Hero、主补丁摘要、fix family、patch 区都显示骨架屏。

### 成功态

- 按主结论 -> 主补丁 -> 家族 -> patch -> trace 的顺序展示。

### 空结果态

- 明确显示“未找到可信补丁”，但保留 trace 与来源信息，便于复核。

### 部分成功态

- 有 patch 元数据但无 diff 内容：patch 区可见，diff 查看区提示不可用。
- 有 trace 但 family 为空：仍可展示 trace 与中间证据。

### 失败态

- run 不存在：展示空态并允许返回工作台。
- diff 加载失败：局部提示，不影响主页面其他区块。

---

## 📦 页面视图对象

### `CVERunDetailView`

| 字段名 | 类型 | 说明 |
|--------|------|------|
| `run_id` | string | 运行 ID |
| `cve_id` | string | CVE 编号 |
| `status` | string | 状态 |
| `stop_reason` | string | 停止原因 |
| `summary` | object | 运行摘要 |
| `fix_families` | array | 补丁家族 |
| `patches` | array | 补丁记录 |
| `source_traces` | array | 页面探索证据 |

### `PatchDiffPanelState`

| 字段名 | 类型 | 说明 |
|--------|------|------|
| `candidate_url` | string | 当前查看的补丁 URL |
| `loading` | boolean | 是否正在加载 diff |
| `content_available` | boolean | 是否存在 diff 内容 |
| `error_message` | string | diff 读取错误 |

---

## 🔌 API 与字段映射

| 页面区块 | API | 主要字段 |
|----------|-----|----------|
| Verdict Hero / 家族 / Trace | `GET /api/v1/cve/runs/{run_id}` | `summary`、`fix_families`、`source_traces` |
| Patch 列表 | `GET /api/v1/cve/runs/{run_id}/patches` | patch 元数据与下载状态 |
| Diff Viewer | `GET /api/v1/cve/runs/{run_id}/patch-content?candidate_url=...` | diff 文本内容 |

---

## 🪞 参考资产与约束

- 继承 `CVELookupCard.tsx` 中的 Verdict Hero 组织方式。
- 继承 `PatchDiffViewer.tsx` 的大文本差异阅读模式。
- 不把原始 trace JSON 作为默认展示方式。

---

## 🔄 变更记录

### v1.0 - 2026-04-09
- 新增 CVE 运行详情页面规格

---

**文档版本**：v1.0  
**创建日期**：2026-04-09  
**最后更新**：2026-04-09  
**维护人**：AI + 开发团队
