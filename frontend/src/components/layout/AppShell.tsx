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
  { to: "/cve", label: "CVE 补丁检索" },
  { to: "/announcements", label: "安全公告提取" },
];

const utilityNavigation: NavigationItem[] = [
  { to: "/deliveries", label: "投递中心" },
  { to: "/system/health", label: "系统", activePrefixes: ["/system/"] },
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
          <p className="brand-kicker">AetherFlow</p>
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
        </div>
      </header>

      <main className="page-shell">
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
  );
}
