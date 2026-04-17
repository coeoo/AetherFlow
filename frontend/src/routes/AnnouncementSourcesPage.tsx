import { Link } from "react-router-dom";
import { AppShell } from "../components/layout/AppShell";

import {
  getSourceTypeLabel,
  useAnnouncementSources,
  useRunAnnouncementSourceNow,
} from "../features/announcements/hooks";

export function AnnouncementSourcesPage() {
  const sourcesQuery = useAnnouncementSources();
  const runNow = useRunAnnouncementSourceNow();

  return (
    <AppShell
      eyebrow="公告监控"
      title="监控源管理"
      description="当前先提供最小源列表与立即试跑入口，后续再补动态表单与启停控制。"
      actions={
        <div className="action-row">
          <Link className="action-link" to="/announcements">
            返回手动提取
          </Link>
          <Link className="action-link action-link-muted" to="/announcements?tab=monitoring">
            查看批次结果
          </Link>
        </div>
      }
    >
      <section className="cve-workbench-grid">
        <section className="cve-panel cve-panel-featured">
          <div className="cve-panel-header">
            <p className="card-label">源列表</p>
            <h2>已配置监控源</h2>
          </div>
          {sourcesQuery.data?.length ? (
            sourcesQuery.data.map((source) => (
              <article key={source.source_id} className="cve-inline-progress">
                <strong>{source.name}</strong>
                <span>
                  {getSourceTypeLabel(source.source_type)} · {source.schedule_cron} ·{" "}
                  {source.enabled ? "启用中" : "已停用"}
                </span>
              </article>
            ))
          ) : (
            <p className="card-copy">当前没有已配置的公告监控源。</p>
          )}
        </section>

        <section className="cve-panel">
          <div className="cve-panel-header">
            <p className="card-label">试跑</p>
            <h2>立即验证来源</h2>
          </div>
          {sourcesQuery.data?.map((source) => (
            <div key={source.source_id} className="action-row">
              <button
                className="action-link action-link-obsidian"
                type="button"
                onClick={() => runNow.mutate(source.source_id)}
              >
                立即试跑
              </button>
              <span className="card-copy">{getSourceTypeLabel(source.source_type)} 源</span>
            </div>
          ))}
          {runNow.data ? <p className="card-copy">试跑任务已创建</p> : null}
        </section>
      </section>
    </AppShell>
  );
}
