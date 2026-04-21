from app.cve.browser.a11y_pruner import KEEP_ROLES
from app.cve.browser.a11y_pruner import MAX_A11Y_CHARS
from app.cve.browser.a11y_pruner import prune_accessibility_tree
from app.cve.browser.base import BrowserBackend
from app.cve.browser.base import BrowserPageSnapshot
from app.cve.browser.base import PageLink
from app.cve.browser.markdown_extractor import MAX_MARKDOWN_CHARS
from app.cve.browser.markdown_extractor import extract_markdown_from_html
from app.cve.browser.page_role_classifier import classify_page_role
from app.cve.browser.playwright_backend import PlaywrightBackend
from app.cve.browser.playwright_backend import PlaywrightPool
from app.cve.browser.sync_bridge import SyncBrowserBridge

__all__ = [
    "BrowserBackend",
    "BrowserPageSnapshot",
    "KEEP_ROLES",
    "MAX_A11Y_CHARS",
    "MAX_MARKDOWN_CHARS",
    "PageLink",
    "PlaywrightBackend",
    "PlaywrightPool",
    "SyncBrowserBridge",
    "classify_page_role",
    "extract_markdown_from_html",
    "prune_accessibility_tree",
]
