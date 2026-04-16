import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { AppShell } from "../components/layout/AppShell";
import { announcementMonitoringPlaceholder } from "../features/announcements/monitoring-placeholder";
import {
  useAnnouncementRunDetail,
  useAnnouncementSources,
  useCreateAnnouncementRun,
  getSourceTypeLabel,
} from "../features/announcements/hooks";

export function AnnouncementWorkbenchPage() {
  const [searchParams] = useSearchParams();
  const [sourceUrl, setSourceUrl] = useState("https://example.com/advisory");
  const [validationMessage, setValidationMessage] = useState<string | null>(null);
  const [activeRunId, setActiveRunId] = useState<string | null>(null);
  const activeTab = searchParams.get("tab");
  const isMonitoringTab = activeTab === "monitoring";
  const createRun = useCreateAnnouncementRun();
  const detailQuery = useAnnouncementRunDetail(activeRunId);
  const sourcesQuery = useAnnouncementSources();
  const detail = detailQuery.data;

  function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!/^https?:\/\//.test(sourceUrl.trim())) {
      setValidationMessage("请输入合法的公告 URL，例如 https://example.com/advisory");
      return;
    }

    setValidationMessage(null);
    createRun.mutate(sourceUrl.trim(), {
      onSuccess: (run) => {
        setActiveRunId(run.run_id);
      },
    });
  }

  return (
    <AppShell
      eyebrow="安全公告场景"
      title="安全公告工作台"
      description={
        isMonitoringTab
          ? announcementMonitoringPlaceholder.description
          : "输入一篇公告 URL，先看结论，再进入详情页继续复核情报包。"
      }
      actions={
        <div className="action-row">
          <Link className="action-link" to="/announcements?tab=monitoring">
            查看监控批次
          </Link>
          <Link className="action-link action-link-muted" to="/announcements/sources">
            管理监控源
          </Link>
        </div>
      }
    >
      {isMonitoringTab ? (
        <section className="cve-workbench-grid">
          <section className="cve-panel cve-panel-featured">
            <div className="cve-panel-header">
              <p className="card-label">监控概览</p>
              <h2>{announcementMonitoringPlaceholder.status}</h2>
            </div>
            <p className="card-copy">{announcementMonitoringPlaceholder.description}</p>
          </section>

          <section className="cve-panel">
            <div className="cve-panel-header">
              <p className="card-label">已配置来源</p>
              <h2>当前监控源</h2>
            </div>
            {sourcesQuery.data?.length ? (
              sourcesQuery.data.map((source) => (
                <article key={source.source_id} className="cve-inline-progress">
                  <strong>{source.name}</strong>
                  <span>
                    {getSourceTypeLabel(source.source_type)} · {source.schedule_cron}
                  </span>
                </article>
              ))
            ) : (
              <p className="card-copy">当前还没有可展示的监控源。</p>
            )}
          </section>
        </section>
      ) : (
        <section className="cve-workbench-grid">
          <form className="cve-panel cve-panel-featured" onSubmit={handleSubmit}>
            <div className="cve-panel-header">
              <p className="card-label">输入区</p>
              <h2>开始一次公告提取</h2>
            </div>
            <label className="cve-field" htmlFor="announcement-url-input">
              <span className="cve-field-label">公告 URL</span>
              <input
                id="announcement-url-input"
                className="cve-input"
                value={sourceUrl}
                onChange={(event) => setSourceUrl(event.target.value)}
                placeholder="https://example.com/advisory"
              />
            </label>
            {validationMessage ? <p className="cve-error-copy">{validationMessage}</p> : null}
            <div className="action-row">
              <button className="action-link action-link-obsidian" disabled={createRun.isPending} type="submit">
                {createRun.isPending ? "创建中…" : "开始提取"}
              </button>
            </div>
          </form>

          <section className="cve-panel">
            <div className="cve-panel-header">
              <p className="card-label">运行状态</p>
              <h2>当前阶段与摘要</h2>
            </div>
            <p className={`status-pill status-pill-${detail?.status ?? "queued"}`}>{detail?.status ?? "idle"}</p>
            <p className="card-copy">当前阶段：{detail?.stage ?? "尚未开始"}</p>
            <p className="card-copy">
              判定结果：
              {detail?.summary.linux_related === true
                ? " Linux 相关"
                : detail?.summary.linux_related === false
                  ? " 暂未命中 Linux 线索"
                  : " 待生成"}
            </p>
          </section>

          <section className="cve-panel cve-verdict-card">
            <div className="cve-panel-header">
              <p className="card-label">结论摘要</p>
              <h2>{detail?.document?.title ?? "等待结论形成"}</h2>
            </div>
            <p className="card-copy">{detail?.package?.analyst_summary ?? "运行完成后会在这里显示分析师摘要。"}</p>
            <p className="card-copy">来源：{detail?.document?.source_name ?? "未生成"}</p>
            {detail ? (
              <div className="action-row">
                <Link className="action-link action-link-obsidian" to={`/announcements/runs/${detail.run_id}`}>
                  查看详情
                </Link>
              </div>
            ) : null}
          </section>
        </section>
      )}
    </AppShell>
  );
}
