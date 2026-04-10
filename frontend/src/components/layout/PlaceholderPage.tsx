import type { ReactNode } from "react";

import { AppShell } from "./AppShell";

type PlaceholderSection = {
  title: string;
  body: string;
};

type PlaceholderPageProps = {
  eyebrow: string;
  title: string;
  description: string;
  status: string;
  sections: PlaceholderSection[];
  actions?: ReactNode;
};

export function PlaceholderPage({
  eyebrow,
  title,
  description,
  status,
  sections,
  actions,
}: PlaceholderPageProps) {
  return (
    <AppShell eyebrow={eyebrow} title={title} description={description} actions={actions}>
      <section className="summary-grid" aria-label={`${title} 页面摘要`}>
        <article className="summary-card summary-card-emphasis">
          <p className="card-label">当前阶段</p>
          <p className="status-pill">{status}</p>
          <p className="card-copy">当前为 Phase 1 前端路由壳，占位内容用于固定路径、导航和页面层级。</p>
        </article>

        {sections.map((section) => (
          <article key={section.title} className="summary-card">
            <h2>{section.title}</h2>
            <p className="card-copy">{section.body}</p>
          </article>
        ))}
      </section>
    </AppShell>
  );
}
