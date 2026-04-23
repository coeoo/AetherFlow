# 浏览器 Agent 真实验收收口分析

日期：2026-04-23

## 结论

当前浏览器 Agent 主链已经在真实 DashScope OpenAI 兼容配置下完成两条真实验收：

- `CVE-2022-2509`：`mailing_list_page -> tracker_page -> commit_page -> patch download`
- `CVE-2024-3094`：多链路跨域场景，能够从 `tracker_page` 跨域收敛到 `oss-security`，并直接下载上游 commit patch

本轮收口后，真实 acceptance 结果为：

- `CVE-2022-2509`：`PASS`
- `CVE-2024-3094`：`PASS`

## 当前实现路径

### 路径 A：CVE-2022-2509

1. 从 Debian 安全公告页进入 `tracker_page`
2. 从 package tracker 进入目标 `CVE-2022-2509` tracker
3. 在目标 tracker 页优先选中真实上游 GitLab commit
4. 进入 `commit_page`
5. 如果 commit 页被 Cloudflare challenge 拦截，则从 commit URL 本身派生 `.patch` 候选
6. 执行 `try_candidate_download`
7. 下载成功后以 `patches_downloaded` 收口

### 路径 B：CVE-2024-3094

1. 从 Debian tracker 进入 `oss-security` 邮件列表
2. 在邮件列表页直接识别多个高质量上游 GitHub commit patch
3. 不再继续扩展无意义链路，而是直接进入 `try_candidate_download`
4. patch 下载成功后以 `patches_downloaded` 收口

## 之前为什么没有打通

### 1. tracker 页对 commit 链接优先级不够

早期 frontier 构建虽然能识别 `commit_page`，但在真实 `tracker_page` 上：

- `NVD advisory`
- `bugtracker`
- 其它 tracker 噪声链接

会和 commit 链接一起竞争 `max_children_per_node`。由于打分不够偏向 `commit_page`，真实上游 commit 常常被挤出前排，导致：

- LLM 可见链接集与真正可推进链路不一致
- 即使目标 tracker 页存在真实 commit，也可能没有进入后续 frontier

### 2. 早期 LLM 预算过低

真实验收中，`max_llm_calls=2` 只能完成：

1. 公告页 -> package tracker
2. package tracker -> 目标 CVE tracker

还来不及在目标 tracker 页完成“进入 commit”的关键一步。

### 3. commit 页被 Cloudflare challenge 拦截

即使后续已经成功走到 GitLab `commit_page`，真实页面仍可能返回 challenge 页面：

- `Just a moment...`
- `Checking your browser before accessing`

如果只依赖页面正文和提取到的链接，系统会得到：

- `commit_page` 已访问
- 但没有 `patch candidate`
- 最终 `no_patch_candidates`

### 4. 真实供应商配置最初未固化

最初 acceptance 运行环境既缺少数据库，也缺少 LLM 供应商配置，导致早期失败中混杂了：

- 环境缺失
- 真实 LLM 行为
- 真实页面反爬

三类问题，定位成本过高。

## 本轮关键修复

### 修复 1：固化本地私有 LLM 配置

- `config.py` 支持自动读取仓库根目录 `.env.local`
- `.env.local` 被 Git 忽略，用于本机私有模型配置

### 修复 2：真实验收预算参数化

`acceptance_browser_agent.py` 现支持：

- `--llm-wall-clock-timeout-seconds`
- `--diagnostic-timeout-seconds`
- `--max-llm-calls`
- `--max-pages-total`

并将实际生效预算写入 `acceptance_report.json`

### 修复 3：tracker 页优先推进 commit

在 `tracker_page` 上提高：

- `commit_page`
- `download_page`

的优先级，同时压低：

- `advisory_page`
- `bugtracker_page`

确保真实修复链路不会被噪声 frontier 挤掉。

### 修复 4：commit 页 challenge fallback

当页面角色已是 `commit_page` 时，即使正文不可用，也会从 commit URL 自身派生：

- `github_commit_patch`
- `gitlab_commit_patch`

从而允许下载链继续推进。

## 真实验收结果摘要

### CVE-2022-2509

- 结果：`PASS`
- 关键 patch：
  - `https://gitlab.com/gnutls/gnutls/-/commit/ce37f9eb265dbe9b6d597f5767449e8ee95848e2.patch`
- 关键页面角色：
  - `mailing_list_page`
  - `tracker_page`
  - `commit_page`

### CVE-2024-3094

- 结果：`PASS`
- 关键 patch：
  - `https://github.com/tukaani-project/xz/commit/e5faaebbcf02ea880cfc56edc702d4f7298788ad.patch`
  - `https://github.com/tukaani-project/xz/commit/72d2933bfae514e0dbb123488e9f1eb7cf64175f.patch`
  - `https://github.com/tukaani-project/xz/commit/6e636819e8f070330d835fce46289a3ff72a7b89.patch`
  - `https://github.com/tukaani-project/xz/commit/82ecc538193b380a21622aea02b0ba078e7ade92.patch`
  - `https://github.com/tukaani-project/xz/commit/cf44e4b7f5dfdbf8c78aef377c10f71e274f63c0.patch`
- 关键特征：
  - 多链路
  - 跨域跳转
  - 至少一条链从 `tracker_page` 收敛到上游 patch

## 推荐运行参数

### CVE-2022-2509

- `LLM_WALL_CLOCK_TIMEOUT_SECONDS=90`
- `AETHERFLOW_CVE_RUNTIME_DIAGNOSTIC_TIMEOUT_SECONDS=360`
- `max_llm_calls=4`
- `max_pages_total=12`

### CVE-2024-3094

- `LLM_WALL_CLOCK_TIMEOUT_SECONDS=90`
- `AETHERFLOW_CVE_RUNTIME_DIAGNOSTIC_TIMEOUT_SECONDS=360`
- `max_llm_calls=6`
- `max_pages_total=16`

## 当前剩余风险

1. 真实 GitLab / GitHub 页面仍可能返回不同形式的 challenge，当前 fallback 依赖 URL 形态而不是页面正文
2. 真实供应商 LLM 仍存在时延波动，虽然当前预算已足以通过这两个场景，但不应假设所有样本都同样稳定
3. `backend/results/` 中已经积累多轮历史验收产物，后续如要做持续回归，需要约定保留策略和命名规范
