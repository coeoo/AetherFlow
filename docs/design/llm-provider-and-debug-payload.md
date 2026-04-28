# LLM Provider 与 Debug Payload 实现设计

> 本文描述 AetherFlow 中 CVE Agent 使用 OpenAI 兼容模型服务的配置读取、
> 请求 payload、响应校验和调试日志。目标是避免再次把“shell 没有环境变量”
> 误判为“应用缺配置”。

## 1. 模块定位

本模块属于 `Decision`、`Runtime` 和 `Observability` 边界。

它解决的问题：

- 统一读取本地私有 LLM 配置。
- 构造 OpenAI 兼容 `/chat/completions` 请求。
- 约束导航决策和候选判断必须返回 JSON object。
- 记录 LLM 成功决策和失败诊断。
- 明确 `.env.local`、环境变量、文档模板和源码之间的边界。

它不解决的问题：

- 不选择具体模型厂商。
- 不保存真实 API Key。
- 不绕过 provider 的鉴权、限流或内容格式错误。
- 不把 LLM Supervisor 引入主图路由。

## 2. 配置入口

配置定义：

- `backend/app/config.py::Settings`
- `backend/app/config.py::load_settings`

本地配置文件：

- 仓库根目录 `.env.local`
- 由 `config.py::_load_local_env_file` 自动读取。
- 已被 Git 忽略，适合放本机私有模型配置。

读取顺序：

```text
load_settings()
  -> _load_local_env_file()
  -> 读取 os.environ
  -> 构造 Settings
```

`.env.local` 规则：

- 忽略空行。
- 忽略 `#` 开头的注释。
- 只处理包含 `=` 的行。
- 去掉 key 两侧空白。
- 如果同名 key 已经存在于 `os.environ`，不覆盖。
- value 两侧同类型引号会被剥离。

因此，终端里直接执行 `echo $LLM_API_KEY` 为空，并不能证明应用缺配置。
必须通过 `load_settings()` 判断应用真实配置。

## 3. 模型配置项

必需配置：

- `LLM_BASE_URL`
  - OpenAI 兼容 API base，例如 `https://example.com/v1`。
- `LLM_API_KEY`
  - provider API Key。
  - 任何日志、文档、测试输出都不得打印真实值。
- `LLM_DEFAULT_MODEL`
  - 默认模型名。

可选配置：

- `LLM_REASONING_EFFORT`
  - 非空时加入导航决策 request body。
- `LLM_TIMEOUT_SECONDS`
  - 单次 HTTP 请求 timeout。
  - 小于等于 0 时传 `timeout=None`。
- `LLM_WALL_CLOCK_TIMEOUT_SECONDS`
  - 总时钟超时。
  - 通过 `future.result(timeout=...)` 强制收口。
- `LLM_RETRY_ATTEMPTS`
  - 导航决策重试次数。

Candidate Judge 开关：

- `AETHERFLOW_CVE_CANDIDATE_JUDGE_ENABLED`
  - 默认 `False`。
  - 只控制候选二次判断，不控制导航决策。

## 4. 导航决策入口

代码入口：

- `backend/app/cve/browser_agent_llm.py::build_llm_page_view`
- `backend/app/cve/browser_agent_llm.py::build_navigation_context`
- `backend/app/cve/browser_agent_llm.py::call_browser_agent_navigation`
- `backend/app/cve/browser_agent_llm.py::_append_llm_decision_log`
- `backend/app/cve/browser_agent_llm.py::_append_llm_failure_log`

Prompt：

- `backend/app/cve/prompts/browser_agent_navigation.md`

调用方：

- `backend/app/cve/decisions/navigation.py`
- `backend/app/cve/agent_nodes.py::agent_decide_node`

## 5. 导航输入 Payload 契约

页面视图：

- `LLMPageView.url`
- `LLMPageView.page_role`
- `LLMPageView.title`
- `LLMPageView.accessibility_tree_summary`
- `LLMPageView.key_links`
- `LLMPageView.patch_candidates`
- `LLMPageView.page_text_summary`

链接视图：

- `LLMLink.url`
- `LLMLink.text`
- `LLMLink.context`
- `LLMLink.is_cross_domain`
- `LLMLink.estimated_target_role`

导航上下文：

- `NavigationContext.cve_id`
- `NavigationContext.budget_remaining`
- `NavigationContext.navigation_path`
- `NavigationContext.parent_page_summary`
- `NavigationContext.current_page`
- `NavigationContext.active_chains`
- `NavigationContext.discovered_candidates`
- `NavigationContext.visited_domains`

`build_llm_page_view` 的 key links 选择规则：

- 如果传入 `frontier_candidates`，按 `score` 倒序取前 `MAX_KEY_LINKS=15`。
- 否则从 `snapshot.links` 中按 `_score_link_for_llm` 评分取前 15。
- commit、patch、diff、merge request、pull 等 URL 关键词会加分。
- 命中目标 CVE ID 会大幅加分。
- 命中非目标 CVE ID 会扣分。

## 6. 导航请求契约

HTTP 请求：

```text
POST {LLM_BASE_URL}/chat/completions
Authorization: Bearer <LLM_API_KEY>
Content-Type: application/json
```

request body：

```json
{
  "model": "<LLM_DEFAULT_MODEL>",
  "response_format": {"type": "json_object"},
  "messages": [
    {
      "role": "system",
      "content": "<browser_agent_navigation.md>"
    },
    {
      "role": "user",
      "content": "<NavigationContext JSON>"
    }
  ]
}
```

如果 `LLM_REASONING_EFFORT` 非空，补充：

```json
{
  "reasoning_effort": "<LLM_REASONING_EFFORT>"
}
```

请求执行：

- 使用 `ThreadPoolExecutor(max_workers=1)` 包装 `http_client.post`。
- `http_client.post` 使用 `LLM_TIMEOUT_SECONDS` 作为底层 timeout。
- `future.result(timeout=LLM_WALL_CLOCK_TIMEOUT_SECONDS)` 强制总时限。
- 最多尝试 `LLM_RETRY_ATTEMPTS` 次。
- 最后一次失败会写入 `_llm_decision_log`。

## 7. 导航输出 Schema

导航决策必需字段：

- `action`
- `reason_summary`
- `confirmed_page_role`
- `selected_urls`
- `selected_candidate_keys`
- `cross_domain_justification`
- `chain_updates`
- `new_chains`

解析流程：

```text
response.raise_for_status()
payload = response.json()
content = payload["choices"][0]["message"]["content"]
decision = json.loads(content)
decision 必须是 dict
必需字段必须齐全
decision["model_name"] = settings.llm_default_model
```

如果缺字段：

```text
ValueError("browser_agent_navigation 缺少字段: ...")
```

如果解析后不是 object：

```text
ValueError("browser_agent_navigation 返回结果不是 JSON object")
```

## 8. Candidate Judge Provider 契约

Candidate Judge 使用同一组 LLM 配置：

- `LLM_BASE_URL`
- `LLM_API_KEY`
- `LLM_DEFAULT_MODEL`
- `LLM_TIMEOUT_SECONDS`

代码入口：

- `backend/app/cve/decisions/candidate_judge.py::call_candidate_judge`

请求特点：

- 同样调用 `/chat/completions`。
- 同样使用 `response_format={"type": "json_object"}`。
- system prompt 来自 `backend/app/cve/prompts/candidate_judge.md`。
- user content 是 `CandidateJudgeContext` 的 JSON。

和导航决策不同：

- 当前 Candidate Judge 没有 wall-clock executor 包装。
- 当前 Candidate Judge 没有 retry loop。
- 当前 Candidate Judge 的 provider 非 JSON 响应会生成带 status、content-type、body preview 的诊断错误。

## 9. Debug Payload 与日志

成功导航决策日志：

```text
state["_llm_decision_log"].append({
  "cve_id": ...,
  "step_index": ...,
  "page_url": ...,
  "page_role": ...,
  "action": ...,
  "selected_urls": [...],
  "selected_candidate_keys": [...],
  "reason_summary": ...,
  "cross_domain": bool,
  "latency_ms": ...,
  "model_name": ...
})
```

失败导航决策日志：

```text
state["_llm_decision_log"].append({
  "cve_id": ...,
  "step_index": ...,
  "page_url": ...,
  "page_role": ...,
  "action": "llm_call_failed",
  "selected_urls": [],
  "selected_candidate_keys": [],
  "reason_summary": str(error),
  "cross_domain": false,
  "latency_ms": ...,
  "model_name": ...,
  "error_type": type(error).__name__
})
```

日志约束：

- 可以记录模型名。
- 可以记录延迟、action、URL、候选 key。
- 不得记录 `LLM_API_KEY`。
- 不得把 Authorization header 写入 artifact、decision 或日志。

## 10. 错误与降级

缺配置：

- 导航决策：`RuntimeError("missing_provider_config")`。
- Candidate Judge：`RuntimeError("missing_provider_config")`。
- 主链处理：
  - 导航失败时 `agent_decide_node` 回退规则引擎。
  - Candidate Judge 失败时保留原候选下载决策。

HTTP 超时：

- 导航决策底层 timeout 来自 `LLM_TIMEOUT_SECONDS`。
- wall-clock timeout 来自 `LLM_WALL_CLOCK_TIMEOUT_SECONDS`。
- 最后一次失败写入 `_llm_decision_log`。

provider 返回非 JSON：

- 导航决策：`response.json()` 或 `json.loads(content)` 抛错，进入规则 fallback。
- Candidate Judge：抛出带 provider context 的错误，主链保留原候选。

schema 缺字段：

- 导航决策：抛出 `ValueError`，进入规则 fallback。
- Candidate Judge：抛出 `ValueError`，主链保留原候选。

## 11. 测试映射

配置加载：

- `backend/tests/test_phase2_schema_contract.py::test_phase2_settings_include_runtime_defaults`
- `backend/tests/test_phase2_schema_contract.py::test_load_settings_reads_root_env_local_without_overriding_existing_env`
- `backend/tests/test_cve_agent_decisions.py::test_candidate_judge_feature_flag_defaults_to_disabled`
- `backend/tests/test_cve_agent_decisions.py::test_candidate_judge_feature_flag_can_be_enabled`

导航 payload 和 LLM 调用：

- `backend/tests/test_browser_agent_llm.py`
- `backend/tests/test_cve_agent_decisions.py::test_navigation_decision_client_builds_context_and_calls_llm`

Candidate Judge provider：

- `backend/tests/test_cve_agent_decisions.py::test_candidate_judge_client_parses_structured_response`
- `backend/tests/test_cve_agent_decisions.py::test_candidate_judge_client_reports_non_json_provider_response`

建议验证命令：

```bash
timeout 60s ./.venv/bin/python -m pytest backend/tests/test_phase2_schema_contract.py backend/tests/test_browser_agent_llm.py backend/tests/test_cve_agent_decisions.py -q
```

## 12. 源码复刻清单

如果源码丢失，按以下顺序复刻：

1. 在 `Settings` 中定义 LLM 配置字段。
2. 实现 `.env.local` 加载逻辑，确保不覆盖已有环境变量。
3. 实现 `build_llm_page_view`，限制 key links 数量并按价值排序。
4. 实现 `build_navigation_context`，包含预算、路径、父页面摘要、活跃链路和候选。
5. 实现 `call_browser_agent_navigation`：
   - 校验必需配置。
   - 构造 OpenAI 兼容 request body。
   - 支持 `response_format=json_object`。
   - 支持 retry 和 wall-clock timeout。
   - 校验必需字段。
6. 实现 `_append_llm_decision_log` 和 `_append_llm_failure_log`。
7. 在 `agent_decide_node` 中接入导航调用，并在异常时进入规则 fallback。
8. 复刻 Candidate Judge provider 调用和非 JSON 诊断。
9. 补齐配置加载、payload 构造、解析失败和 fallback 测试。

## 13. 已知差距

导航决策和 Candidate Judge 当前共用基础 LLM 配置，但超时、重试和错误诊断能力
不完全一致。后续如果 Candidate Judge 从实验开关变成默认链路，应把 wall-clock
timeout、retry 和统一失败日志补齐。
