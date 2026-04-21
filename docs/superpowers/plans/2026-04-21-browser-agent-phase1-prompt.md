# Phase 1 开发提示词：浏览器基础设施

你正在 `/opt/projects/demo/aetherflow` 仓库中实现 CVE Patch 浏览器驱动型 AI Agent 的 Phase 1。

## 权威参考

- 设计规格：`docs/superpowers/specs/2026-04-21-cve-browser-agent-design.md`（第 3 节"浏览器层设计"）
- 模块设计：`docs/04-功能设计/M103-CVE数据源与页面探索规则功能设计.md`

## 本轮目标

实现浏览器基础设施层，包含 `backend/app/cve/browser/` 完整包，使后续 Phase 2/3 可以直接调用浏览器导航。

## 交付物

### 1. `backend/app/cve/browser/__init__.py`

导出公共接口。

### 2. `backend/app/cve/browser/base.py`

定义核心协议和数据类：

```python
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

@dataclass(frozen=True)
class PageLink:
    url: str
    text: str
    context: str                  # a11y 树中相邻节点的文本
    is_cross_domain: bool
    estimated_target_role: str    # URL 推断的目标页面角色

@dataclass(frozen=True)
class BrowserPageSnapshot:
    url: str
    final_url: str
    status_code: int
    title: str
    raw_html: str
    accessibility_tree: str       # 裁剪后的 a11y 树（≤6000字符）
    markdown_content: str         # Readability 提取后的 markdown（≤2000字符）
    links: list[PageLink]         # 结构化链接列表
    page_role_hint: str           # 启发式页面角色
    fetch_duration_ms: int

@runtime_checkable
class BrowserBackend(Protocol):
    async def start(self) -> None: ...
    async def stop(self) -> None: ...
    async def navigate(self, url: str, *, timeout_ms: int = 30000) -> BrowserPageSnapshot: ...
```

### 3. `backend/app/cve/browser/playwright_backend.py`

实现 PlaywrightPool 和 PlaywrightBackend：

- `PlaywrightPool`：管理固定数量的 BrowserContext（通过 asyncio.Queue）
  - `__init__(self, *, pool_size: int = 3, headless: bool = True)`
  - `async def start(self) -> None`：启动浏览器进程，创建 pool_size 个 BrowserContext
  - `@asynccontextmanager async def acquire(self) -> AsyncIterator[BrowserContext]`：从池中获取上下文
  - `async def stop(self) -> None`：关闭所有上下文和浏览器进程

- `PlaywrightBackend(BrowserBackend)`：
  - 内部持有 PlaywrightPool
  - `navigate` 方法：
    1. 从池中获取 BrowserContext
    2. 创建新 page
    3. `page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)`
    4. 调用 `page.accessibility.snapshot()` 获取 a11y 树
    5. 调用 `page.content()` 获取 raw_html
    6. 在页面内执行 JS 提取结构化链接（href + innerText + 周围文本）
    7. 调用 a11y_pruner 裁剪 a11y 树
    8. 调用 markdown_extractor 提取 markdown
    9. 调用 page_role_classifier 分类页面角色
    10. 构建 BrowserPageSnapshot 返回

### 4. `backend/app/cve/browser/sync_bridge.py`

同步桥接层，供 LangGraph 同步节点调用：

```python
class SyncBrowserBridge:
    """在独立线程事件循环中运行 async 浏览器操作，暴露同步接口"""
    def __init__(self, backend: BrowserBackend): ...
    def start(self) -> None: ...
    def navigate(self, url: str, *, timeout_ms: int = 30000) -> BrowserPageSnapshot: ...
    def stop(self) -> None: ...
```

实现方式：
- `__init__` 时创建独立 daemon 线程运行 `asyncio.new_event_loop()`
- `start()` 通过 `run_coroutine_threadsafe` 调用 `backend.start()`
- `navigate()` 通过 `run_coroutine_threadsafe` 调用 `backend.navigate()`
- `stop()` 通过 `run_coroutine_threadsafe` 调用 `backend.stop()`，然后关闭事件循环和线程

### 5. `backend/app/cve/browser/a11y_pruner.py`

可访问性树裁剪器：

```python
MAX_A11Y_CHARS = 6000
KEEP_ROLES = {"link", "heading", "text", "list", "listitem", "paragraph", "table", "row", "cell", "StaticText"}

def prune_accessibility_tree(raw_snapshot: dict) -> str:
    """
    接收 Playwright page.accessibility.snapshot() 的原始输出，
    递归遍历树，只保留 KEEP_ROLES 中的节点，
    序列化为缩进文本树格式，截断到 MAX_A11Y_CHARS。
    """
```

输出格式示例：
```
heading "CVE-2022-2509"
  text "GnuTLS Double Free vulnerability"
  list
    listitem
      link "upstream fix" -> https://gitlab.com/gnutls/gnutls/-/commit/ce37f9eb
      text "Fixed in gnutls28 3.7.7-2"
    listitem
      link "Debian Bug #1234" -> https://bugs.debian.org/1234
```

### 6. `backend/app/cve/browser/page_role_classifier.py`

URL 启发式页面角色分类：

```python
def classify_page_role(url: str) -> str:
    """
    基于 URL 模式返回页面角色字符串。
    
    返回值之一：
    - "advisory_page"：nvd.nist.gov, GHSA, vuln/detail
    - "tracker_page"：security-tracker.debian.org, errata
    - "mailing_list_page"：oss-security, debian-security-announce
    - "bugtracker_page"：bugzilla, show_bug
    - "commit_page"：/commit/, /pull/, /merge_requests/
    - "download_page"：.patch, .diff, .debdiff
    - "repository_page"：代码仓库根目录
    - "unknown_page"：无法分类
    """
```

### 7. `backend/app/cve/browser/markdown_extractor.py`

Markdown 提取器：

```python
MAX_MARKDOWN_CHARS = 2000

def extract_markdown_from_html(raw_html: str) -> str:
    """
    从 raw_html 中提取纯文本 markdown。
    使用 Python 端的 HTML→text 转换（如 html2text 或 beautifulsoup 简化）。
    截断到 MAX_MARKDOWN_CHARS。
    """
```

注意：不需要在浏览器内执行 Readability.js，用 Python 端 html2text 库即可（已在项目中可用或可引入）。

### 8. 配置更新 `backend/app/config.py`

在 Settings 中新增：

```python
cve_browser_backend: str = "playwright"
cve_browser_pool_size: int = 3
cve_browser_headless: bool = True
cve_browser_timeout_ms: int = 30000
cve_browser_cdp_endpoint: str = ""
```

删除以下旧配置（如存在）：
- `cve_agent_graph_enabled`
- `cve_llm_fallback_enabled`
- `cve_browser_enabled`

### 9. 依赖更新 `backend/pyproject.toml`

添加：
- `playwright>=1.40`
- `html2text>=2024.2`（如果不存在）

## 验收标准

必须通过以下测试（新建 `backend/tests/test_browser_infra.py`）：

1. **PlaywrightPool 生命周期**：start → acquire → navigate 到一个简单页面 → release → stop
2. **a11y_pruner**：给定一个模拟 a11y snapshot dict，输出 ≤6000 字符的文本树
3. **page_role_classifier**：正确分类以下 URL：
   - `https://security-tracker.debian.org/tracker/CVE-2022-2509` → `tracker_page`
   - `https://nvd.nist.gov/vuln/detail/CVE-2022-2509` → `advisory_page`
   - `https://github.com/user/repo/commit/abc123` → `commit_page`
   - `https://gitlab.com/org/proj/-/merge_requests/42` → `commit_page`
   - `https://example.com/file.patch` → `download_page`
   - `https://www.openwall.com/lists/oss-security/2022/08/01/1` → `mailing_list_page`
4. **SyncBrowserBridge**：在同步上下文中调用 navigate，正确返回 BrowserPageSnapshot
5. **markdown_extractor**：给定简单 HTML，输出 ≤2000 字符的 markdown 文本

## 约束

- 所有代码注释使用简体中文
- 遵循项目现有代码风格（查看 `backend/app/cve/` 下现有文件）
- 不修改现有测试（除非删除旧的 fast-first 相关测试）
- 不修改 `agent_nodes.py`、`agent_graph.py`、`runtime.py`（Phase 3 才改）
- 测试中使用真实 Playwright（需要 `playwright install chromium`），不 mock 浏览器

## 现有代码参考

- `backend/app/cve/page_fetcher.py`：旧的 httpx 抓取（看结构但不继承）
- `backend/app/cve/frontier_planner.py`：URL 优先级评分（保留复用）
- `backend/app/cve/reference_matcher.py`：URL 模式匹配（保留复用）
- `backend/app/config.py`：现有配置结构
- `backend/pyproject.toml`：现有依赖声明
