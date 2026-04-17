import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { AppShell } from "../components/layout/AppShell";
import {
  useAnnouncementMonitorRunDetail,
  useAnnouncementMonitorRuns,
  useAnnouncementRunDetail,
  useCreateAnnouncementRun,
  getSourceTypeLabel,
} from "../features/announcements/hooks";

export function AnnouncementWorkbenchPage() {
  const [searchParams] = useSearchParams();
  const [sourceUrl, setSourceUrl] = useState("https://example.com/advisory");
  const [validationMessage, setValidationMessage] = useState<string | null>(null);
  const [activeRunId, setActiveRunId] = useState<string | null>(null);
  const [activeFetchId, setActiveFetchId] = useState<string | null>(null);
  const activeTab = searchParams.get("tab");
  const isMonitoringTab = activeTab === "monitoring";
  const createRun = useCreateAnnouncementRun();
  const detailQuery = useAnnouncementRunDetail(activeRunId);
  const monitorRunsQuery = useAnnouncementMonitorRuns();
  const monitorRunDetailQuery = useAnnouncementMonitorRunDetail(activeFetchId);
  const detail = detailQuery.data;
  const monitorRuns = monitorRunsQuery.data ?? [];
  const monitorDetail = monitorRunDetailQuery.data;

  useEffect(() => {
    if (!isMonitoringTab || monitorRuns.length === 0) {
      return;
    }
    if (activeFetchId && monitorRuns.some((batch) => batch.fetch_id === activeFetchId)) {
      return;
    }
    setActiveFetchId(monitorRuns[0]!.fetch_id);
  }, [activeFetchId, isMonitoringTab, monitorRuns]);

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
          ? "按批次查看监控抓取结果，并继续进入关联公告 run 详情。"
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
              <p className="card-label">最近批次</p>
              <h2>公告监控批次</h2>
            </div>
            {monitorRunsQuery.isLoading ? <p className="card-copy">正在加载监控批次…</p> : null}
            {!monitorRunsQuery.isLoading && monitorRuns.length === 0 ? (
              <p className="card-copy">当前还没有监控批次记录。</p>
            ) : null}
            {monitorRuns.map((batch) => (
              <button
                key={batch.fetch_id}
                className="cve-inline-progress"
                type="button"
                onClick={() => setActiveFetchId(batch.fetch_id)}
              >
                <strong>{batch.source_name}</strong>
                <span>
                  {getSourceTypeLabel(batch.source_type)} · {batch.status} · {batch.created_at}
                </span>
                <span>
                  发现 {batch.discovered_count} · 新增 {batch.new_count} · 提取 {batch.extraction_run_count}
                </span>
              </button>
            ))}
          </section>

          <section className="cve-panel">
            <div className="cve-panel-header">
              <p className="card-label">批次详情</p>
              <h2>{monitorDetail?.source_name ?? "选择一个批次查看详情"}</h2>
            </div>
            {monitorRunDetailQuery.isLoading ? <p className="card-copy">正在加载批次详情…</p> : null}
            {!monitorRunDetailQuery.isLoading && !monitorDetail ? (
              <p className="card-copy">请选择左侧批次，查看本次抓取及关联 run。</p>
            ) : null}
            {monitorDetail ? (
              <>
                <p className={`status-pill status-pill-${monitorDetail.status}`}>{monitorDetail.status}</p>
                <p className="card-copy">
                  {getSourceTypeLabel(monitorDetail.source_type)} · 发现 {monitorDetail.discovered_count} · 新增{" "}
                  {monitorDetail.new_count} · 提取 {monitorDetail.extraction_run_count}
                </p>
                {monitorDetail.error_message ? (
                  <p className="cve-error-copy">批次错误：{monitorDetail.error_message}</p>
                ) : null}
                {monitorDetail.triggered_runs.length ? (
                  monitorDetail.triggered_runs.map((run) => (
                    <article key={run.run_id} className="cve-inline-progress">
                      <strong>{run.title_hint ?? run.run_id}</strong>
                      <span>
                        {run.status} · {run.stage}
                      </span>
                      <span>{run.source_url ?? "无来源 URL"}</span>
                      <div className="action-row">
                        <Link
                          className="action-link action-link-obsidian"
                          aria-label={`查看 run 详情 ${run.title_hint ?? run.run_id}`}
                          to={`/announcements/runs/${run.run_id}`}
                        >
                          查看 run 详情
                        </Link>
                      </div>
                    </article>
                  ))
                ) : (
                  <p className="card-copy">当前批次还没有关联的公告 run。</p>
                )}
              </>
            ) : null}
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
