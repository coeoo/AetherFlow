# Phase 2 开发提示词：LLM 接口 + 链路追踪

你正在 `/opt/projects/demo/aetherflow` 仓库中实现 CVE Patch 浏览器驱动型 AI Agent 的 Phase 2。

## 前提

Phase 1 已完成，以下模块可直接使用：
- `backend/app/cve/browser/base.py`（BrowserPageSnapshot、PageLink、BrowserBackend）
- `backend/app/cve/browser/playwright_backend.py`（PlaywrightPool、PlaywrightBackend）
- `backend/app/cve/browser/sync_bridge.py`（SyncBrowserBridge）
- `backend/app/cve/browser/a11y_pruner.py`
- `backend/app/cve/browser/page_role_classifier.py`
- `backend/app/cve/browser/markdown_extractor.py`

## 权威参考

- 设计规格：`docs/superpowers/specs/2026-04-21-cve-browser-agent-design.md`（第 4/5/8 节）
- 模块设计：`docs/04-功能设计/M103-CVE数据源与页面探索规则功能设计.md`

## 本轮目标

实现 LLM 导航接口、链路追踪器和导航提示词，使 Phase 3 的节点重写可以直接调用。

## 交付物

### 1. `backend/app/cve/chain_tracker.py`

链路追踪管理器：

```python
from dataclasses import dataclass, field
import uuid

@dataclass
class ChainStep:
    url: str
    page_role: str
    depth: int

@dataclass
class NavigationChain:
    chain_id: str
    chain_type: str             # "advisory_to_patch", "tracker_to_commit", "mailing_list_to_fix"
    steps: list[ChainStep] = field(default_factory=list)
    status: str = "in_progress" # "in_progress", "completed", "dead_end"
    expected_next_roles: list[str] = field(default_factory=list)

class ChainTracker:
    """管理一次 run 中所有 NavigationChain 的生命周期"""

    def __init__(self) -> None:
        self._chains: dict[str, NavigationChain] = {}

    def create_chain(self, *, chain_type: str, initial_url: str, page_role: str, depth: int = 0) -> NavigationChain:
        """创建新链路，自动推断 expected_next_roles"""

    def extend_chain(self, chain_id: str, *, url: str, page_role: str, depth: int) -> None:
        """向链路追加一步，更新 expected_next_roles"""

    def complete_chain(self, chain_id: str) -> None:
        """标记链路已完成（找到 patch 或到达终点）"""

    def mark_dead_end(self, chain_id: str) -> None:
        """标记链路为死胡同"""

    def get_active_chains(self) -> list[NavigationChain]:
        """返回所有 in_progress 的链路"""

    def get_all_chains(self) -> list[NavigationChain]:
        """返回所有链路"""

    def to_dict_list(self) -> list[dict]:
        """序列化为可存入 AgentState 的 dict 列表"""

    @classmethod
    def from_dict_list(cls, data: list[dict]) -> "ChainTracker":
        """从 AgentState 中恢复"""
```

链路类型到 expected_next_roles 的映射：

```python
CHAIN_TYPE_EXPECTATIONS = {
    "advisory_to_patch": {
        "advisory_page": ["tracker_page", "commit_page", "download_page"],
        "tracker_page": ["commit_page", "download_page"],
        "commit_page": ["download_page"],
    },
    "tracker_to_commit": {
        "tracker_page": ["commit_page", "download_page"],
        "commit_page": ["download_page"],
    },
    "mailing_list_to_fix": {
        "mailing_list_page": ["commit_page", "download_page"],
        "commit_page": ["download_page"],
    },
}
```

### 2. `backend/app/cve/browser_agent_llm.py`

浏览器 Agent 专用 LLM 接口：

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class LLMLink:
    url: str
    text: str
    context: str
    is_cross_domain: bool
    estimated_target_role: str

@dataclass(frozen=True)
class LLMPageView:
    url: str
    page_role: str
    title: str
    accessibility_tree_summary: str   # ≤6000字符
    key_links: list[LLMLink]          # 前 15 个
    patch_candidates: list[dict[str, str]]
    page_text_summary: str            # ≤2000字符

@dataclass(frozen=True)
class NavigationContext:
    cve_id: str
    budget_remaining: dict[str, int]
    navigation_path: list[str]
    parent_page_summary: str | None
    current_page: LLMPageView
    active_chains: list[dict]
    discovered_candidates: list[dict]
    visited_domains: list[str]

MAX_KEY_LINKS = 15

def build_llm_page_view(snapshot: BrowserPageSnapshot, candidates: list[dict]) -> LLMPageView:
    """从 BrowserPageSnapshot 构建 LLMPageView"""

def build_navigation_context(state: dict, page_view: LLMPageView) -> NavigationContext:
    """从 AgentState + LLMPageView 构建完整的 NavigationContext"""

def call_browser_agent_navigation(context: NavigationContext) -> dict:
    """
    调用 LLM 获取导航决策。
    
    1. 加载 prompts/browser_agent_navigation.md 作为系统提示词
    2. 将 NavigationContext 序列化为 JSON 作为用户消息
    3. 调用 OpenAI 兼容接口（settings.llm_base_url）
    4. 解析返回的 JSON，确保包含 action、reason_summary、selected_urls 等字段
    5. 附加 model_name 到返回值
    """
```

参考现有 `backend/app/cve/agent_llm.py` 的 LLM 调用模式（httpx 调用 OpenAI 兼容接口），但输入结构完全不同。

### 3. `backend/app/cve/prompts/browser_agent_navigation.md`

完整提示词内容见设计规格第 8.1 节。核心要点：

- 身份：CVE Patch Agent 的浏览器导航决策器
- 核心能力：页面理解（a11y 树）、链路追踪、导航决策、停止判断
- 页面角色定义（7 种）
- 典型链路模式（3 种）
- 硬性约束（5 条）
- 输出 Schema：action / reason_summary / confirmed_page_role / selected_urls / selected_candidate_keys / cross_domain_justification / chain_updates / new_chains

### 4. `backend/app/cve/agent_state.py` 更新

在 AgentState TypedDict 中追加新字段：

```python
navigation_chains: list[dict[str, object]]    # NavigationChain 列表
current_chain_id: str | None                   # 当前活跃链路 ID
page_role_history: list[dict[str, str]]        # [{url, role, title, depth}]
cross_domain_hops: int                         # 已用跨域次数
browser_snapshots: dict[str, dict]             # URL → BrowserPageSnapshot 序列化
```

在 `build_initial_agent_state` 中初始化这些字段。

## 验收标准

新建 `backend/tests/test_chain_tracker.py`：

1. 创建 advisory_to_patch 链路，验证初始 expected_next_roles 正确
2. extend_chain 后 expected_next_roles 更新
3. complete_chain / mark_dead_end 正确更新状态
4. get_active_chains 只返回 in_progress 的
5. to_dict_list / from_dict_list 往返序列化一致

新建 `backend/tests/test_browser_agent_llm.py`：

1. build_llm_page_view 正确裁剪 key_links 到 15 个
2. build_navigation_context 包含所有必要字段
3. call_browser_agent_navigation 使用 fake HTTP server 验证请求载荷结构（包含 a11y 树、链路上下文）

更新 `backend/tests/test_cve_agent_graph.py`：
1. 验证新增的 AgentState 字段在 build_initial_agent_state 中被正确初始化

## 约束

- 所有代码注释使用简体中文
- `call_browser_agent_navigation` 复用现有 `app.http_client` 和 `app.config.load_settings()` 模式
- 不修改 `agent_nodes.py`、`agent_graph.py`、`runtime.py`（Phase 3 才改）
- 不删除 `agent_llm.py`（Phase 3 废弃时一并删除）
