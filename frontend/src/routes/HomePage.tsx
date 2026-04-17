import { Link } from "react-router-dom";

import { AppShell } from "../components/layout/AppShell";
import { useHomeSummary } from "../features/home/hooks";
import {
  getRecentJobTitle,
  getSceneActionLabel,
  getScenePath,
  getSceneTitle,
} from "../features/home/presentation";
import { getPlatformHealthItems, getPlatformHealthLevel } from "../features/system/presentation";
import { getTaskRunLink } from "../features/tasks/presentation";

export function HomePage() {
  const homeSummaryQuery = useHomeSummary();
  const summary = homeSummaryQuery.data;
  const healthSummary = summary?.health;
  const healthItems = healthSummary ? getPlatformHealthItems(healthSummary) : [];
  const healthLevel = healthSummary ? getPlatformHealthLevel(healthSummary) : "down";
  const recentJobs = summary?.recent_jobs ?? [];
  const recentDeliveries = summary?.recent_deliveries ?? [];
  const sceneCards = summary?.scenes ?? [];

  return (
    <AppShell
      eyebrow="平台首页"
      title={summary?.platform_name ?? "平台首页"}
      description={
        summary?.platform_tagline ??
        "平台首页负责承接场景入口、最近任务、投递摘要和系统健康的首屏定位。"
      }
      actions={
        <div className="action-row">
          {sceneCards.map((scene, index) => (
            <Link
              key={scene.scene_name}
              className={index === 0 ? "action-link" : "action-link action-link-muted"}
              to={getScenePath(scene)}
            >
              {getSceneActionLabel(scene)}
            </Link>
          ))}
        </div>
      }
    >
      <section className="dashboard-stat-grid" aria-label="平台首页摘要">
        <article className="summary-card summary-card-spotlight">
          <p className="card-label">场景总数</p>
          <h2>{sceneCards.length}</h2>
          <p className="card-copy">当前工作区已经接入首页、Patch 检索、安全公告提取等主路径。</p>
        </article>

        <article className="summary-card">
          <p className="card-label">最近任务</p>
          <h2>{recentJobs.length}</h2>
          <p className="card-copy">任务中心承接平台执行层状态、attempt 轨迹和关联结果入口。</p>
        </article>

        <article className="summary-card">
          <p className="card-label">最近投递</p>
          <h2>{recentDeliveries.length}</h2>
          <p className="card-copy">投递中心统一管理目标、记录、测试发送和失败重试。</p>
        </article>

        <article className="summary-card summary-card-emphasis">
          <p className="card-label">系统健康</p>
          <h2>{healthSummary ? "运行正常" : "等待健康摘要"}</h2>
          <p className={`status-pill status-pill-${healthLevel}`}>
            {homeSummaryQuery.isLoading ? "loading" : healthLevel}
          </p>
          <p className="card-copy">健康摘要由 API、Database、Worker、Scheduler 四个维度汇总。</p>
        </article>
      </section>

      <section className="workspace-overview-grid">
        <div className="workspace-main-column">
          <article className="summary-card summary-card-emphasis summary-card-spotlight">
            <div className="cve-panel-header">
              <p className="card-label">场景入口</p>
              <h2>当前主路径</h2>
            </div>
            <div className="summary-grid">
              {sceneCards.map((scene) => (
                <article key={scene.scene_name} className="summary-inline-item">
                  <strong>{getSceneTitle(scene)}</strong>
                  <span>{scene.description}</span>
                  <span>{scene.recent_status}</span>
                  <div className="action-row">
                    <Link className="action-link action-link-muted" to={getScenePath(scene)}>
                      {getSceneActionLabel(scene)}
                    </Link>
                  </div>
                </article>
              ))}
            </div>
          </article>

          <article className="summary-card summary-card-stream">
            <div className="cve-panel-header">
              <p className="card-label">最近结果流</p>
              <h2>任务概览</h2>
            </div>
            {recentJobs.length ? (
              <div className="stack-sm">
                {recentJobs.slice(0, 3).map((job) => (
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

          <article className="summary-card summary-card-stream">
            <div className="cve-panel-header">
              <p className="card-label">最近投递</p>
              <h2>投递记录</h2>
            </div>
            {recentDeliveries.length ? (
              <div className="stack-sm">
                {recentDeliveries.slice(0, 3).map((record) => (
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
        </div>

        <aside className="workspace-side-column">
          <article className="summary-card summary-card-rail">
            <div className="cve-panel-header">
              <p className="card-label">系统状态</p>
              <h2>{healthSummary ? "平台健康摘要" : "等待健康摘要"}</h2>
            </div>
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
                {healthSummary.notes.slice(0, 3).map((note) => (
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

          <article className="promo-card">
            <p className="card-label">情报工作区</p>
            <h3>全站已经切入统一后台骨架</h3>
            <p className="card-copy">
              这一轮只替换前端空间结构和视觉语言，保留中文命名、现有路由和现有后端逻辑。
            </p>
            <div className="action-row">
              <Link className="action-link action-link-muted" to="/patch">
                进入 Patch 检索
              </Link>
            </div>
          </article>
        </aside>
      </section>
    </AppShell>
  );
}
