import type { PropsWithChildren, ReactNode } from "react";
import { NavLink, useLocation } from "react-router-dom";

type NavigationItem = {
  to: string;
  label: string;
  activePrefixes?: string[];
};

type AppShellProps = PropsWithChildren<{
  eyebrow: string;
  title: string;
  description: string;
  actions?: ReactNode;
}>;

const primaryNavigation: NavigationItem[] = [
  { to: "/", label: "首页" },
  { to: "/patch", label: "Patch 检索" },
  { to: "/announcements", label: "安全公告提取" },
];

const utilityNavigation: NavigationItem[] = [
  { to: "/deliveries", label: "投递中心" },
  { to: "/system/health", label: "系统", activePrefixes: ["/system/"] },
];

const workspaceNavigation: NavigationItem[] = [
  { to: "/", label: "首页总览" },
  { to: "/patch", label: "Patch 检索工作区" },
  { to: "/announcements", label: "安全公告提取工作区", activePrefixes: ["/announcements"] },
  { to: "/deliveries", label: "投递中心工作区", activePrefixes: ["/deliveries"] },
  { to: "/system/tasks", label: "任务中心" },
  { to: "/system/health", label: "系统状态", activePrefixes: ["/system/"] },
];

export function AppShell({
  eyebrow,
  title,
  description,
  actions,
  children,
}: AppShellProps) {
  const location = useLocation();

  const getLinkClassName = (item: NavigationItem, isActive: boolean) => {
    const isPrefixActive = item.activePrefixes?.some((prefix) => location.pathname.startsWith(prefix));
    return `nav-link${isActive || isPrefixActive ? " nav-link-active" : ""}`;
  };

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand-block">
          <p className="brand-kicker">AETHERFLOW</p>
          <span className="brand-copy">把原始安全信号处理成可复查的结构化情报</span>
        </div>

        <div className="nav-group">
          <nav aria-label="主导航" className="nav-row">
            {primaryNavigation.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) => getLinkClassName(item, isActive)}
              >
                {item.label}
              </NavLink>
            ))}
          </nav>

          <div className="topbar-tools">
            <label className="topbar-search" htmlFor="platform-shell-search">
              <span className="topbar-search-icon" aria-hidden="true">
                ⌕
              </span>
              <input
                id="platform-shell-search"
                aria-label="搜索参数"
                className="topbar-search-input"
                placeholder="搜索参数..."
                type="search"
              />
            </label>

            <nav aria-label="工具导航" className="nav-row nav-row-utility">
              {utilityNavigation.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  className={({ isActive }) => getLinkClassName(item, isActive)}
                >
                  {item.label}
                </NavLink>
              ))}
            </nav>

            <div className="topbar-avatar" aria-hidden="true">
              AF
            </div>
          </div>
        </div>
      </header>

      <div className="page-shell">
        <aside className="workspace-sidebar">
          <div className="workspace-sidebar-header">
            <div className="workspace-sidebar-mark">◼</div>
            <div className="workspace-sidebar-copy">
              <strong>{title}</strong>
              <span>{eyebrow}</span>
            </div>
          </div>

          <nav aria-label="场景导航" className="workspace-nav">
            {workspaceNavigation.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) => getLinkClassName(item, isActive)}
              >
                {item.label}
              </NavLink>
            ))}
          </nav>

          <div className="workspace-sidebar-footer">
            <div className="workspace-sidebar-note">
              <strong>Workspace</strong>
              <span>保持现有中文场景和路由，只替换成统一后台骨架。</span>
            </div>
          </div>
        </aside>

        <main className="workspace-main">
          <section className="hero-card">
            <div className="hero-copy">
              <p className="eyebrow">{eyebrow}</p>
              <h1>{title}</h1>
              <p className="hero-description">{description}</p>
            </div>
            {actions ? <div className="hero-actions">{actions}</div> : null}
          </section>

          {children}
        </main>
      </div>
    </div>
  );
}
