# Session017：CVE 浏览器 Agent 真实验收收口

日期：2026-04-23

## 本轮目标

把浏览器 Agent 从“离线测试通过”推进到“真实供应商 + 真实页面 + 真实 PostgreSQL 验收通过”，并给出：

- 当前可用实现路径
- 之前为什么没有打通
- 稳定可复用的本地运行方式

## 真实环境准备

### 1. 本地模型配置

将 DashScope OpenAI 兼容配置写入仓库根目录 `.env.local`，并在 `config.py` 中增加自动读取逻辑：

- `LLM_BASE_URL`
- `LLM_API_KEY`
- `LLM_DEFAULT_MODEL`

同时在 `.gitignore` 中忽略 `.env.local`，避免私有 key 进入版本控制。

### 2. 本地数据库

使用：

`postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev`

并在真实 acceptance 前确认 `infra-postgres-1` 处于 healthy。

## 本轮真实问题定位过程

### 第一阶段：环境问题

最初 acceptance 直接失败，不是业务逻辑问题，而是：

- 缺少 `DATABASE_URL`
- 缺少 `LLM_BASE_URL / LLM_API_KEY / LLM_DEFAULT_MODEL`

处理方式：

- 启动本地 PostgreSQL
- 固化 `.env.local`

### 第二阶段：预算问题

第一次真实跑 `CVE-2022-2509` 时，`max_llm_calls=2` 只能走到目标 tracker，还没进入 commit。

结论：

- `max_llm_calls=2` 不足以覆盖完整链路
- acceptance 脚本必须支持可调预算，而不能写死

处理方式：

- 给 `acceptance_browser_agent.py` 增加：
  - `--llm-wall-clock-timeout-seconds`
  - `--diagnostic-timeout-seconds`
  - `--max-llm-calls`
  - `--max-pages-total`

### 第三阶段：tracker 页选路问题

后续真实 run 表明：

- 目标 `tracker_page` 已经能看到真实 GitLab commit
- 但 `commit_page` 会在 frontier children 限额下输给 NVD / bugtracker 等噪声链接

结论：

- tracker 页必须明确偏向 `commit_page`

处理方式：

- 提升 `tracker_page` 来源下 `commit_page` / `download_page` 权重
- 压低 `advisory_page` / `bugtracker_page`

### 第四阶段：commit 页 challenge 问题

即使进入真实 GitLab commit 页面，也可能碰到：

- `Just a moment...`
- `Checking your browser before accessing`

此时页面正文提取不到 patch，但 commit URL 本身已经足够派生 `.patch`。

结论：

- `commit_page` 不能只靠正文
- 必须支持 URL 级 patch fallback

处理方式：

- 在 `extract_links_and_candidates_node` 中，当页面角色为 `commit_page` 时，直接对当前页 URL 运行 `match_reference_url`
- challenge 页面判定增加 Cloudflare 常见文案

## 本轮真实验收结果

### CVE-2022-2509

- 最终结果：`PASS`
- 收口路径：
  `mailing_list_page -> tracker_page -> commit_page -> patch download`

### CVE-2024-3094

- 最终结果：`PASS`
- 收口路径：
  `tracker_page -> oss-security -> 直接下载高质量 GitHub commit patch`

## 当前推荐参数

### CVE-2022-2509

```bash
DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev \
AETHERFLOW_CVE_RUNTIME_DIAGNOSTIC_MODE=true \
python -m scripts.acceptance_browser_agent \
  --cve CVE-2022-2509 \
  --llm-wall-clock-timeout-seconds 90 \
  --diagnostic-timeout-seconds 360 \
  --max-llm-calls 4 \
  --max-pages-total 12
```

### CVE-2024-3094

```bash
DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev \
AETHERFLOW_CVE_RUNTIME_DIAGNOSTIC_MODE=true \
python -m scripts.acceptance_browser_agent \
  --cve CVE-2024-3094 \
  --llm-wall-clock-timeout-seconds 90 \
  --diagnostic-timeout-seconds 360 \
  --max-llm-calls 6 \
  --max-pages-total 16
```

## 本轮结论

到本轮结束时，浏览器 Agent 已从“设计与测试可行”推进到“真实验收通过”。

真正打通的关键不是单个补丁，而是三条工程原则：

1. 真实模型配置必须本地固化
2. 真实 acceptance 必须参数化预算
3. `tracker_page` 和 `commit_page` 都要有面向真实页面噪声的 fallback，而不是只依赖理想页面正文
