# Backend 日志约定

> stdlib logging 真实使用模式。当前**未引入**结构化日志框架（如 structlog / loguru）。

---

## 1. 当前现状

- 用 Python stdlib `logging`，模块级 logger
- **未引入**结构化日志框架（structlog / loguru / json formatter）
- 日志格式约定：`[<场景前缀>:<id>] <动作描述>`，参数通过 `%s` 占位符传入

如未来需要引入结构化日志，应该按 `docs/design/llm-provider-and-debug-payload.md` 等设计文档先评估再做。

---

## 2. Logger 创建模式

参考 `backend/app/cve/runtime.py:24`：

```python
import logging

_logger = logging.getLogger(__name__)
```

要点：

- **模块级**变量名 `_logger`（带前导下划线表示模块私有）
- 用 `__name__`，不要硬编码字符串
- 不要在函数体内反复 `getLogger`

---

## 3. 日志级别使用

实际代码统计模式：

| 级别 | 何时使用 | 真实样例 |
|------|----------|----------|
| `info` | 关键里程碑（开始/完成、阶段切换、决策结果） | `_logger.info("[CVE:%s] 开始执行 run=%s", run.cve_id, run_id)` |
| `warning` | 可恢复异常、降级路径、超出预算软停 | `_logger.warning(...)` (参考 `runtime.py:149`) |
| `exception` | 异常路径，自动捕获 traceback；**优先于 `error`** | `_logger.exception("[CVE:%s] 节点执行失败", run.cve_id)` (`runtime.py:93`) |
| `error` | 明确错误但无 traceback 上下文（罕见，几乎都用 exception 代替） | — |
| `debug` | 当前生产代码使用极少；调试期可开 | — |

**首选 `exception` 而非 `error`**：traceback 对 CVE Agent 长链路调试至关重要。

---

## 4. 消息格式约定

### 场景前缀

CVE 场景统一用 `[CVE:<cve_id>]` 前缀，便于按 cve_id grep 整条链路：

```python
_logger.info("[CVE:%s] bridge.start() 完成", run.cve_id)
_logger.info("[CVE:%s] graph.invoke() 开始", run.cve_id)
_logger.info("[CVE:%s] 诊断模式开启，使用逐节点执行", run.cve_id)
```

公告场景类似：`[Announcement:<run_id>] ...`（按 announcement runtime 现状）。

### 占位符

- **必须**用 `%s` / `%d` 占位符，**不要**用 f-string 或 `%` 拼接
- 理由：占位符让 logging 框架在过滤后才格式化，省 CPU；也避免误格式化包含 `{}` 的内容
- 反例：`_logger.info(f"开始执行 {run_id}")` ❌
- 正例：`_logger.info("开始执行 %s", run_id)` ✅

---

## 5. 应该记录什么

- **平台任务边界**：`task_job` 创建 / 领取 / 完成 / 失败
- **场景节点边界**：每个图节点的进入与退出（CVE：resolve_seeds / build_initial_frontier / agent_decide / download_and_validate / finalize_run）
- **决策落地**：Agent 决策类型、命中工具、候选数量
- **降级路径**：fallback 触发原因（如：navigator 失败转 rule fallback）
- **外部调用**：LLM 请求 ID、HTTP 状态码、抓取耗时
- **预算消耗**：剩余 budget、本节点消耗

---

## 6. 不应该记录的

- **不要记录 `LLM_API_KEY`、cookie、token、私钥**（即使脱敏后也优先 `set/missing` 标记）
- **不要把整个 patch 内容、HTML 全文打进日志**——走 Artifact 持久化，日志只放引用 ID
- **不要在 happy path 反复打 debug 级日志噪音**——保持 info 级可读
- **不要把用户输入的可疑文本不加引号塞进日志**——可能含换行符或控制字符干扰 grep

---

## 7. 异常处理与日志的协作

```python
try:
    result = node_func(state)
except Exception:
    _logger.exception("[CVE:%s] 节点 %s 执行失败 round=%s", cve_id, node_name, round_index)
    raise  # 让 runtime 上层翻译成 stop_reason
```

要点：

- 用 `_logger.exception(...)`（自动捕获 traceback）
- **不要吞异常**——记录后必须 raise，让上层处理
- 异常 message 要带场景 ID + 节点名 + 关键参数（round / candidate_key 等）

---

## 8. 禁止

- **不要在生产代码 `print(...)`**——一律走 logger
- **不要静默吞异常**（参见 `error-handling.md`）
- **不要打印任何 `LLM_API_KEY` 真实值**
- **不要在多线程/Worker 进程间假定日志顺序**——Worker 多实例并发，日志按 cve_id 字段 grep 而非时间顺序
