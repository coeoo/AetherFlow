# Superpowers 过程资产说明

> 本目录用于存放阶段性设计、执行计划与评审记录。
> 这些内容主要服务于开发过程追溯，不是当前实现的长期主规范入口。

---

## 🚦 接手入口

开始阅读或执行 `docs/superpowers/` 中的过程资产前，先读：

1. `docs/superpowers/STATUS.md`：当前 active spec、active plan、下一步 checkpoint。
2. `docs/superpowers/REVIEW_CHECKLIST.md`：执行前先审查 spec / plan 是否仍然可用。
3. `docs/superpowers/DECISIONS.md`：长期架构决策索引。

不要直接从 `plans/` 中随机挑文件执行。`plans/` 里包含历史 prompt、旧阶段计划和已被替代的执行记录。

---

## 🎯 当前使用原则

- 当前接手实现时，优先阅读 `docs/` 下的主文档，尤其是：
  - `docs/00-总设计/`
  - `docs/01-产品介绍/`
  - `docs/04-功能设计/`
  - `docs/13-界面设计/`
- `docs/superpowers/` 只承接阶段性过程资产，不替代上述长期文档。
- 如果过程资产与主文档存在表述差异，以 `docs/` 主文档中的当前定义为准。

---

## 🏷️ 状态语义

每个关键 spec / plan 应尽量在文件头部标注状态：

- `draft`：草稿，不能直接执行。
- `active`：当前执行入口。
- `completed`：已完成并有验收或收口记录。
- `superseded`：已被后续文档替代，不能作为当前实现依据。
- `archived`：历史保留，仅用于追溯。

同一主题只能有一个 active spec 和一个 active plan。active 变化时，必须同步更新 `STATUS.md`。

---

## 📚 子目录含义

### `specs/`

- 用于保存阶段性的规格说明与设计收口。
- 对于 CVE / Patch Agent 相关主题，当前关键规格包括：
  - `docs/superpowers/specs/2026-04-21-cve-browser-agent-design.md`：浏览器 Agent 重设计阶段背景。
  - `docs/superpowers/specs/2026-04-25-cve-agent-boundary-refactor-design.md`：当前 active 的边界重构规格。
- 它不是长期主规范的唯一入口；当前实现定义仍应回到 `docs/04-功能设计/` 等主文档。

### `plans/`

- 用于保存当时的执行计划、阶段 prompt 与推进记录。
- 这些文件可能引用已经删除或已被替代的历史 spec，这是历史冻结结果。
- `plans/` 不能直接作为当前实现入口；必须先通过 `STATUS.md` 确认 active plan。

### `reviews/`

- 用于保存阶段性验收、评审与收口记录。
- 这些文档用于解释某一轮交付如何验收，不承担主规范职责。

---

## 🧊 CVE / Patch Agent 历史说明

- 旧的 `CVE Patch Agent`、`fast-first`、`httpx` 等术语仍可能出现在历史 spec、plan 与 review 中。
- 这些术语反映的是阶段性实现或被替代方案，不代表当前唯一主线。
- 当前 CVE 相关能力的主线已经收口到浏览器驱动型 Browser Agent 语义；若需确认当前实现边界，请回到 `docs/` 主文档。

---

## ⚠️ 阅读建议

- 需要了解“现在应该按什么做”时，不要从 `docs/superpowers/plans/` 开始。
- 需要追溯“为什么当时这样改”时，再回看这里的 spec / plan / review。
- 看到 `plans/` 或 `日志/` 中引用已删除历史 spec，属于预期现象，不表示当前主文档缺失。

---

## ✅ 审查节奏

以下场景必须先审查 Superpowers 过程资产：

- 开始执行新的 active plan。
- 从中断会话恢复。
- 一个计划被连续执行超过一天。
- 准备提交或合并前。
- 新 spec / plan 替代旧文档时。

审查时使用 `docs/superpowers/REVIEW_CHECKLIST.md`。如果发现 plan 与代码、主文档、baseline 或 git 状态不一致，先修正过程资产，再继续执行。
