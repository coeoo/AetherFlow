# Backend 错误处理

> 异常类型、传播链、API 响应格式与禁止项。

---

## 1. 总体原则

来自 `docs/06-开发规范/代码规范.md` §5：

- **快速失败**，错误信息带上下文（CVE ID、run ID、节点名等）
- **不静默吞异常**
- 外部抓取、模型调用、投递失败必须记录可排查信息

---

## 2. API 层响应格式

成功响应（参考 `backend/app/api/v1/cve/runs.py::create_run`）：

```python
return {
    "code": 0,
    "message": "success",
    "data": <serialized payload>,
}
```

> **注意**：当前真实格式是 `{code, message, data}` 三字段，**不是** `{"data": ...}` 单字段或 `{"error": {...}}` 包装。文档若有不一致以代码为准。

错误响应通过 `HTTPException`：

```python
from fastapi import HTTPException

if detail is None:
    raise HTTPException(status_code=404, detail="CVE 运行记录不存在")
if patch_id is None and candidate_url is None:
    raise HTTPException(status_code=422, detail="patch_id 或 candidate_url 至少提供一个")
```

约定：

- 404：资源不存在（`运行记录不存在`、`Patch 内容不存在`）
- 422：请求参数语义错误（缺少必传组合、逻辑校验失败）；纯类型/字段错误由 Pydantic 自动产 422
- 500：未捕获异常，由 FastAPI 默认处理；**必须**先记录 `_logger.exception` 再让其冒泡

`detail` 字段使用简体中文（与项目语言一致）。

---

## 3. 请求体校验

用 Pydantic `BaseModel` + `Field(pattern=...)` 做格式校验：

```python
class CreateCVERunRequest(BaseModel):
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
```

校验失败由 FastAPI 自动转换成 422，不要手写。

---

## 4. Domain 层异常

- 业务异常放 `backend/app/core/errors.py` 或对应场景子模块的 `errors.py`（已有：`LeaseExpiredError`）
- Service 层抛 domain exception，由 API 层捕获后包装为 `HTTPException`
- **不要**在 service 层直接抛 `HTTPException`（会让 service 不能被 worker 复用）

---

## 5. 长任务节点的错误处理

CVE Agent 节点失败由 `backend/app/cve/runtime.py` 统一翻译为 `stop_reason`：

```python
_EXCEPTION_STOP_REASONS = {
    "resolve_seeds": "resolve_seeds_failed",
    "build_initial_frontier": "build_initial_frontier_failed",
    ...
}

def _finalize_failure(run, *, stop_reason, summary):
    run.status = "failed"
    run.stop_reason = stop_reason
    run.summary_json = summary
```

要点：

- 节点抛异常 → runtime 捕获 → 写 `cve_runs.status='failed'` + `stop_reason` + `summary_json`
- **必须** `_logger.exception("[CVE:%s] ...", cve_id)` 留 traceback
- 不要让 worker 主循环挂掉；单个 run 失败要被吸收

---

## 6. 投递与外部调用

- HTTP 抓取（`backend/app/http_client.py`）：超时、重试、失败审计
- 模型调用（LLM）：超时由 `LLM_TIMEOUT_SECONDS` / `LLM_WALL_CLOCK_TIMEOUT_SECONDS` 控制；失败要记录 `LLM_REASONING_EFFORT` 与请求上下文
- 投递失败（`partially_delivered` / `delivery_failed`）：参考 `docs/design/platform-task-runtime.md`，写审计日志（`stage_audit_logs`）

---

## 7. 禁止

- **不要静默 `except Exception: pass`**。最少要 `_logger.exception(...)` + 重新抛或转换为已知错误。
- **不要把 LLM_API_KEY 等敏感字段写进异常 message 或 logger**（参见 `AGENTS.md` §3.2，配置只输出 `set/missing`）。
- **不要在 service 层抛 `HTTPException`**——这会污染 worker 的调用栈语义。
- **不要让节点函数返回 None 表示失败**——必须抛异常，让 runtime 统一翻译。
- **不要把 `code: 0` 改成其他成功码**——前端 hook 已按 `code === 0` 判断成功。
