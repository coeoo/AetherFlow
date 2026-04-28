# AetherFlow 实现设计索引

> 本目录承载长期实现设计，用于把关键模块写到“可按文档复刻源码”的粒度。

## 1. 定位

`docs/design/` 是源码级实现蓝图，不替代以下文档：

- `docs/00-总设计/`：产品和系统总目标。
- `docs/03-系统架构/`：平台级架构和运行形态。
- `docs/04-功能设计/`：功能模块、页面和用户价值。
- `docs/superpowers/specs/`：阶段性规格和背景设计。
- `docs/superpowers/plans/`：当前或历史执行计划。
- `docs/09-AI开发日志/`：会话日志和变更追溯。

本目录只写长期稳定的实现契约：

- 模块边界。
- 代码入口。
- 输入输出。
- 状态字段。
- 数据库读写。
- 错误和降级。
- 测试映射。
- 源码复刻清单。

## 2. 维护规则

新增或重构核心模块时，必须同步补齐对应实现设计。

实现设计必须回到真实代码，不允许只复述产品目标。文档中的入口、函数名、
配置项、状态字段和测试文件必须能在仓库中定位。

若设计和代码不一致，必须显式标注：

- `设计目标`：期望形态。
- `当前实现`：代码真实行为。
- `差距`：后续需要补齐的部分。

`AGENTS.md` 只放协作规则和索引，不承载长篇模块设计。需要长期保留的实现
细节统一放在本目录。

## 3. 文档模板

- [design-template.md](design-template.md)：所有实现设计文档的统一模板。

## 4. CVE Agent 实现设计包

当前设计包聚焦最复杂、最难复刻的 CVE Browser Agent 主链：

- [cve-agent-orchestration.md](cve-agent-orchestration.md)
  - 覆盖 Worker -> runtime -> LangGraph -> node 的编排链路。
- [cve-agent-state-and-budget.md](cve-agent-state-and-budget.md)
  - 覆盖 `AgentState`、预算、frontier、observation 和停止条件。
- [cve-agent-browser-runtime.md](cve-agent-browser-runtime.md)
  - 覆盖 Playwright backend、同步桥、页面快照、a11y 裁剪和 markdown 提取。
- [cve-agent-frontier-and-noise-filter.md](cve-agent-frontier-and-noise-filter.md)
  - 覆盖 seed frontier、页面角色、噪声过滤、高价值链接、fallback URL 选择。
- [cve-agent-decision-layer.md](cve-agent-decision-layer.md)
  - 覆盖 Navigator、规则 fallback、Candidate Judge、决策校验和 decision evidence。
- [cve-agent-search-graph-and-evidence.md](cve-agent-search-graph-and-evidence.md)
  - 覆盖搜索图表、decision、candidate artifact、evidence 聚合和详情读取。
- [cve-agent-patch-downloader.md](cve-agent-patch-downloader.md)
  - 覆盖 patch 下载策略、GitHub/kernel fallback、attempts、错误分类和 artifact 持久化。
- [cve-agent-candidate-judge.md](cve-agent-candidate-judge.md)
  - 覆盖 Candidate Judge 的开关、配置、payload、schema、fallback 和测试。
- [cve-agent-detail-api-and-frontend-projection.md](cve-agent-detail-api-and-frontend-projection.md)
  - 覆盖详情 API、patch content、前端类型、hooks、详情页组件和轮询缓存。
- [llm-provider-and-debug-payload.md](llm-provider-and-debug-payload.md)
  - 覆盖 `.env.local` 配置加载、OpenAI 兼容请求、LLM 决策日志和失败诊断。
- [platform-task-runtime.md](platform-task-runtime.md)
  - 覆盖 TaskJob、TaskAttempt、Worker、Scheduler、heartbeat、任务查询和重排。

后续建议补齐：

- `announcement-runtime-and-source-adapters.md`
- `artifact-store-and-source-trace.md`
- `frontend-application-shell-and-routing.md`

## 5. 复刻验收原则

一篇实现设计只有满足以下条件，才算可用于源码复刻：

1. 能指出主入口文件和主函数。
2. 能描述外部输入如何进入模块。
3. 能描述模块输出写到哪里。
4. 能列出核心状态字段和生命周期。
5. 能说明失败时如何降级或收口。
6. 能指出对应测试和验收命令。
7. 能给出按步骤重建源码的清单。

如果文档只能说明“要做什么”，但不能说明“怎么实现和怎么验收”，则不应放入
本目录，应该放回产品设计、功能设计或执行计划。
