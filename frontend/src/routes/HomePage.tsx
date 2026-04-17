import { Link } from "react-router-dom";

import { AppShell } from "../components/layout/AppShell";
import { useHomeSummary } from "../features/home/hooks";
import { getRecentJobTitle, getSceneActionLabel } from "../features/home/presentation";
import { getPlatformHealthItems, getPlatformHealthLevel } from "../features/system/presentation";
import { getTaskRunLink } from "../features/tasks/presentation";

export function HomePage() {
  const homeSummaryQuery = useHomeSummary();
  const summary = homeSummaryQuery.data;
  const healthSummary = summary?.health;
  const healthItems = healthSummary ? getPlatformHealthItems(healthSummary) : [];
  const healthLevel = healthSummary ? getPlatformHealthLevel(healthSummary) : "down";

  return (
    <AppShell
      eyebrow="平台首页"
      title={summary?.platform_name ?? "平台首页"}
      description={summary?.platform_tagline ?? "平台首页负责承接场景入口、最近任务、投递摘要和系统健康的首屏定位。"}
      actions={
        <div className="action-row">
          {(summary?.scenes ?? []).map((scene, index) => (
            <Link
              key={scene.scene_name}
              className={index === 0 ? "action-link" : "action-link action-link-muted"}
              to={scene.path}
            >
              {getSceneActionLabel(scene)}
            </Link>
          ))}
        </div>
      }
    >
      <section className="summary-grid" aria-label="平台首页摘要">
        {(summary?.scenes ?? []).map((scene) => (
          <article key={scene.scene_name} className="summary-card">
            <p className="card-label">场景入口</p>
            <h2>{scene.title}</h2>
            <p className="card-copy">{scene.description}</p>
            <p className="card-copy">{scene.recent_status}</p>
            <div className="action-row">
              <Link className="action-link action-link-muted" to={scene.path}>
                {getSceneActionLabel(scene)}
              </Link>
            </div>
          </article>
        ))}

        <article className="summary-card summary-card-emphasis">
          <p className="card-label">健康概览</p>
          <h2>{healthSummary ? "平台健康摘要" : "等待健康摘要"}</h2>
          {homeSummaryQuery.isLoading ? <p className="card-copy">正在加载首页摘要…</p> : null}
          {homeSummaryQuery.isError ? (
            <p className="card-copy">首页摘要暂时不可用，请稍后重试。</p>
          ) : null}
          {healthSummary ? (
            <ul className="health-status-list" aria-label="首页健康摘要状态">
              {healthItems.map((item) => (
                <li key={item.key} className="health-status-row">
                  <span>{item.label}</span>
                  <span className={`status-pill status-pill-${item.value}`}>{item.value}</span>
                </li>
              ))}
            </ul>
          ) : null}
          {healthSummary?.notes?.length ? (
            <ul className="health-note-list">
              {healthSummary.notes.slice(0, 2).map((note) => (
                <li key={note} className="health-note-item">
                  {note}
                </li>
              ))}
            </ul>
          ) : null}
          <div className="action-row">
            <Link
              className={`action-link${healthSummary && healthLevel === "down" ? " action-link-obsidian" : ""}`}
              to="/system/health"
            >
              查看系统状态
            </Link>
          </div>
        </article>

        <article className="summary-card">
          <p className="card-label">最近任务</p>
          <h2>最近任务</h2>
          {summary?.recent_jobs?.length ? (
            <div className="stack-sm">
              {summary.recent_jobs.slice(0, 3).map((job) => (
                <article key={job.job_id} className="summary-inline-item">
                  <strong>{getRecentJobTitle(job)}</strong>
                  <span>{job.status}</span>
                  <div className="action-row">
                    <Link className="action-link action-link-muted" to={getTaskRunLink(job) ?? "/system/tasks"}>
                      查看结果
                    </Link>
                  </div>
                </article>
              ))}
            </div>
          ) : (
            <p className="card-copy">当前还没有最近任务。</p>
          )}
          <div className="action-row">
            <Link className="action-link action-link-muted" to="/system/tasks">
              进入任务中心
            </Link>
          </div>
        </article>

        <article className="summary-card">
          <p className="card-label">最近投递</p>
          <h2>最近投递</h2>
          {summary?.recent_deliveries?.length ? (
            <div className="stack-sm">
              {summary.recent_deliveries.slice(0, 3).map((record) => (
                <article key={record.record_id} className="summary-inline-item">
                  <strong>{String(record.payload_summary.title ?? record.target_name)}</strong>
                  <span>
                    {record.target_name} · {record.status}
                  </span>
                </article>
              ))}
            </div>
          ) : (
            <p className="card-copy">当前还没有最近投递。</p>
          )}
          <div className="action-row">
            <Link className="action-link action-link-muted" to="/deliveries?tab=records">
              查看投递记录
            </Link>
          </div>
        </article>
      </section>
    </AppShell>
  );
}
