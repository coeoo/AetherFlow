# 安全公告 Phase 1 + Phase 2 设计规格

> 对应范围：公告核心模型、单文档运行链、Openwall 单源监控闭环
>
> 说明：本规格不把旧项目 `SecurityAnnouncement` 整体搬入当前仓库，而是把其中已经验证过的来源抓取行为与 Linux 相关性判定逻辑迁入 `AetherFlow` 的平台运行模型。

---

## 1. 背景与问题定义

当前仓库已经有可运行的平台底座：

- `task_jobs` / `task_attempts` 任务执行模型
- `artifacts` / `task_attempt_artifacts` Artifact 持久化
- `source_fetch_records` 抓取审计
- `delivery_targets` / `delivery_records` 投递记录
- 公告场景的前端路由壳与数据库设计文档

但安全公告场景仍处于“设计先行、业务未落地”的状态：

- 后端没有 `announcement` 业务模块
- Alembic 尚未真正创建公告域表
- Worker 只消费 `cve`
- 公告页仍是占位路由，没有真实数据查询链

旧项目 `/opt/projects/demo/SecurityAnnouncement` 已验证了三类来源的抓取行为：

- 微信文章源：依赖登录态抓取账号文章，再抓正文
- Openwall：按日期页回溯，过滤回复邮件，抓取正文
- NCC Security Community：用 Playwright 读取 SPA DOM，提取漏洞列表

旧项目还包含一个可复用的 AI 判定逻辑：

- 输入标题与正文，判断是否“Linux 相关”

但旧项目本质上是脚本式流水线，不适合作为平台实现直接迁入：

- 用 RSS 文件做中间契约
- 用 JSON 文件保存幂等、日报和推送状态
- 用单体 `TaskExecutor` 串抓取、分析、通知
- 用桌面坐标点击方式发微信消息

因此，本轮设计目标是：把旧项目中**已验证的来源行为与判定逻辑**迁为平台能力，同时用 `AetherFlow` 的任务、Artifact、场景 run、投递记录模型重建安全公告的最小可运行闭环。

---

## 2. 目标

本规格要交付以下结果：

1. 用 Alembic 和 SQLAlchemy 真正落地公告域四张表：
   - `announcement_sources`
   - `announcement_runs`
   - `announcement_documents`
   - `announcement_intelligence_packages`
2. 提供公告场景最小后端 API：
   - 创建手动 run
   - 查询 run 详情
   - 查询监控源列表
   - 对单个源执行 `run-now`
3. 让 Worker 能消费 `announcement` 场景任务，并生成单文档结果
4. 提供第一版公告结构化结果对象：
   - 标题 / 来源 / 发布时间
   - Linux 相关性
   - 置信度
   - 摘要
   - 是否建议投递
   - Evidence
5. 接入 Openwall 作为第一条监控来源闭环：
   - 创建抓取批次
   - 记录抓取审计
   - 输出标准化文档
   - 对新增文档创建单文档 run
6. 让公告工作台、监控视图和详情页具备最小真实数据展示能力

---

## 3. 非目标

本规格明确不包含以下内容：

- 直接迁入旧项目的 `TaskExecutor`、`Scheduler`、JSON 状态文件
- 继续使用 RSS 文件作为平台主契约
- 一次性接入三类来源
- 一次性实现完整 IOC / remediation / affected_products 提取
- 一次性实现投递中心和自动投递闭环
- 保留桌面坐标式微信通知为主链能力

本轮只聚焦于：

- 公告核心模型
- 单文档运行链
- Openwall 单源监控闭环

---

## 4. 方案选择

### 4.1 候选方案

#### 方案 A：整体搬迁旧项目

优点：

- 初期改动看似最少
- 旧行为短期内可复现

缺点：

- 会把 RSS 中转、JSON 状态、桌面通知一并带入新平台
- 旧项目的单体执行模型会污染当前任务底座
- 后续拆解成本高，测试边界混乱

#### 方案 B：平台壳包裹旧执行器

优点：

- 比整体搬迁风险稍低
- 可以较快跑出 PoC

缺点：

- 依然保留旧项目的中间契约和耦合
- `TaskExecutor` 会成为平台内部的黑盒
- 很难收口到 `announcement_run / document / package` 的标准表达

#### 方案 C：行为迁移 + 平台重写

优点：

- 任务边界、数据边界和前端边界清晰
- 能和当前 `task_jobs` / `source_fetch_records` / `artifacts` 自然对齐
- 后续接入 NCC、WeChat 和投递能力时不会重复返工

缺点：

- 前期工作量更大
- 需要先补齐公告域模型和运行链

### 4.2 推荐方案

本规格选择 **方案 C：行为迁移 + 平台重写**。

选择理由：

- 当前仓库已经有稳定的平台底座，继续引入旧的单体脚本模型会直接破坏边界
- 旧项目最有价值的是来源行为和判定逻辑，而不是它的编排结构
- 先做单源闭环更适合 TDD 和回归验证，风险明显更低

---

## 5. 核心设计

### 5.1 运行模型

公告场景固定使用“单文档 run”模型：

- 一个 `announcement_run` 只处理一篇公告
- 一个 `announcement_document` 唯一从属于一个 `announcement_run`
- 一个 `announcement_intelligence_package` 唯一从属于一个 `announcement_document`

监控批次不由 `announcement_run` 兼任，而是通过平台表 `source_fetch_records` 表达：

- 抓取批次存在于 `source_fetch_records`
- 批次与 run 的关联通过 `announcement_runs.trigger_fetch_id`

### 5.2 两类入口，共享同一处理链

当前设计保留两类入口，但第一阶段只实现其中一类完整监控闭环：

- 手动入口：
  - `POST /api/v1/announcements/runs`
  - 首轮只支持 `input_mode=url`
- 监控入口：
  - `POST /api/v1/announcements/sources/{source_id}/run-now`
  - 首轮只承诺 `openwall`

两类入口共享同一后端处理链：

```text
输入快照
  -> announcement_run
  -> 获取原文
  -> source Artifact
  -> 归一化正文
  -> normalized Artifact
  -> announcement_document
  -> Linux relevance + summary
  -> announcement_intelligence_package
```

### 5.3 来源适配器边界

来源适配器只负责“抓取与标准化”，不负责结构化提取。

统一输出对象：

```python
class StandardSourceDocument(TypedDict):
    source_name: str
    source_type: str
    title: str
    source_url: str
    published_at: str | None
    source_item_key: str
    raw_content: str
    content_dedup_hash: str
```

约束：

- `source_item_key` 是源内稳定幂等键
- `raw_content` 在适配器层拿到后，必须先落 Artifact，再交给上层
- 适配器不直接创建 `announcement_document` 或 `announcement_package`

### 5.4 Openwall 作为第一条闭环来源

首轮只接 Openwall，原因：

- 不依赖登录态
- 不依赖浏览器桌面环境
- 已有旧项目验证过的抓取行为
- 适合先建立批次、去重和单文档 run 的核心契约

迁移时保留这些行为事实：

- 按日期页回溯
- 过滤 `Re:` / `RE:` / `re:` 回复
- 过滤重复标题
- 抓取正文并裁剪超长内容

首轮不继承旧实现中的以下内容：

- 先写 RSS 再解析回文章
- 以本地 JSON 保存已处理 URL

### 5.5 第一版情报包字段

为了尽快形成稳定可用的结果页，第一版情报包只承诺以下字段：

- `title`
- `source_name`
- `source_url`
- `published_at`
- `linux_related`
- `confidence`
- `analyst_summary`
- `notify_recommended`
- `evidence`

其中：

- `linux_related` 来自旧项目的 Linux 判定逻辑迁移
- `confidence` 首轮可使用固定映射：
  - 成功完成且判定明确：`0.90`
  - 仅基于标题推断：`0.65`
  - 解析不完整：`0.35`
- `notify_recommended` 首轮直接等价于：
  - `linux_related is True`

### 5.6 AI 失败语义

旧项目在 AI 调用失败时默认返回 `False`。当前平台不延续这一行为。

首轮约束：

- 如果 AI 调用失败，不把结果静默收口为“非 Linux 相关”
- 允许 `summary_json` 和 package 表达为“低置信度 / 待人工判断”
- run 可收口为 `succeeded`，但 package 中必须体现 `confidence` 降级和 evidence 不完整

这样可以避免把模型故障伪装成业务否定结果。

---

## 6. 数据边界与映射

旧项目的持久化产物迁移原则如下：

- `processed_urls.json`
  - 不再保留
  - 改为 `(source_id, source_item_key)` 幂等键
- `sent_articles.json`
  - 不在本规格中迁移
  - 后续由 `delivery_records` 表达
- `daily_data/*.json`
  - 不在平台中继续作为主存储
  - 需要时通过批次与 run 汇总得到
- `analysis_results/*.json`
  - 改为 `announcement_intelligence_packages`
- `rss_feeds/*`
  - 只作为旧项目调试产物
  - 不进入新平台主链

---

## 7. 后端设计

### 7.1 模型

新增：

- `backend/app/models/announcement.py`

主要模型：

- `AnnouncementSource`
- `AnnouncementRun`
- `AnnouncementDocument`
- `AnnouncementIntelligencePackage`

更新：

- `backend/app/models/__init__.py`

### 7.2 运行服务

新增模块边界：

- `backend/app/announcements/service.py`
  - 创建 run
  - 查询列表
  - 查询监控源
  - `run-now`
- `backend/app/announcements/detail_service.py`
  - 聚合详情页数据
- `backend/app/announcements/runtime.py`
  - Worker 处理单文档 run
- `backend/app/announcements/openwall_adapter.py`
  - Openwall 标准化适配器
- `backend/app/announcements/intelligence.py`
  - Linux relevance + summary

### 7.3 Worker 扩展

当前 `worker/runtime.py` 只消费 `cve`。

首轮需要扩展为：

- 能 claim `announcement` 任务
- 能识别：
  - `announcement_manual_extract`
  - `announcement_monitor_fetch`
- `announcement_monitor_fetch` 负责：
  - 创建 `source_fetch_records`
  - 调用 `OpenwallAdapter`
  - 对新增文档创建单文档 `announcement_run`
- `announcement_manual_extract` 负责：
  - 获取 URL 正文
  - 生成 document / package

### 7.4 API

新增：

- `backend/app/api/v1/announcements/runs.py`
- `backend/app/api/v1/announcements/sources.py`

接入：

- `backend/app/api/router.py`

首轮接口：

- `POST /api/v1/announcements/runs`
- `GET /api/v1/announcements/runs/{run_id}`
- `GET /api/v1/announcements/sources`
- `POST /api/v1/announcements/sources/{source_id}/run-now`

---

## 8. 前端设计

首轮不做完整工作台，只替换掉占位页中的关键区块。

新增边界：

- `frontend/src/features/announcements/types.ts`
- `frontend/src/features/announcements/api.ts`
- `frontend/src/features/announcements/hooks.ts`

改造页面：

- `AnnouncementWorkbenchPage.tsx`
  - 支持最小 URL 提交
  - 支持监控 tab 展示最近抓取批次
- `AnnouncementSourcesPage.tsx`
  - 支持最小源列表
  - 支持单个 `run-now`
- `AnnouncementRunDetailPage.tsx`
  - 支持显示 package 基本结果

首轮 UI 原则：

- 保持现有视觉风格
- 先展示真实数据，不追求完整编辑体验
- 复杂动态表单和投递区块延后

---

## 9. 测试策略

### 9.1 后端

必须先有失败测试，再写实现。

首轮重点测试：

- Alembic `upgrade head` 包含公告域表
- `POST /announcements/runs` 能创建 run + task job
- `GET /announcements/runs/{run_id}` 能返回 detail
- `GET /announcements/sources` 返回列表
- `POST /announcements/sources/{source_id}/run-now` 能创建监控任务
- Openwall adapter 能输出标准文档
- 源内幂等生效，不重复创建 run
- Worker 能消费公告任务

### 9.2 前端

- 路由页不再只是占位
- 工作台可提交 URL
- 监控 tab 可展示批次
- 详情页可展示 package 摘要

---

## 10. 风险与控制

### 风险 1：Openwall 页面结构变更

控制：

- 首轮保留失败审计
- 测试里固化 fixture
- 抓取失败不影响其他任务收口

### 风险 2：手动 URL 获取正文不稳定

控制：

- 首轮只做最小 HTML 抓取与文本提取
- 失败时允许 run 失败并保留 source Artifact

### 风险 3：AI 误判或调用失败

控制：

- 低置信度而不是默认否定
- 结果页显示 evidence 和 confidence

### 风险 4：一次性接太多来源导致实现失控

控制：

- 本规格只承诺 Openwall
- NCC / WeChat 放到后续阶段

---

## 11. 实施阶段

### Phase 1：公告核心模型与单文档运行链

交付：

- 公告域迁移
- 模型
- API
- Worker 单文档处理
- 最小详情页

### Phase 2：Openwall 单源监控闭环

交付：

- Openwall adapter
- 监控源列表 + `run-now`
- 抓取批次记录
- 新增条目创建单文档 run
- 监控 tab 真实数据

后续阶段不在本规格中实施：

- Phase 3：NCC
- Phase 4：来源管理完整 CRUD + Scheduler
- Phase 5：WeChat
- Phase 6：投递能力

---

## 12. 验收标准

本规格完成时，必须满足以下条件：

- Alembic `upgrade head` 后存在公告域四张表
- Worker 能处理公告场景任务
- 能创建手动 URL run 并生成 package
- 能对 Openwall 源执行 `run-now`
- 能在监控视图看到抓取批次
- 能从批次进入单文档详情页
- 前端不再只是公告占位页

---

## 13. 实现结论

本轮不做“旧项目迁入”，只做“行为迁移 + 平台重写”。

第一批实现边界明确为：

- 公告核心链
- Openwall 单源闭环

只要这两部分落地，后续再接 NCC、WeChat、投递能力时就能沿同一平台模型平滑扩展，而不会重新回到脚本式流水线。
