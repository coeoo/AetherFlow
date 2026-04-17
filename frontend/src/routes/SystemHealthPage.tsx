import { Link } from "react-router-dom";

import { AppShell } from "../components/layout/AppShell";
import { usePlatformHealthSummary } from "../features/system/hooks";
import { getPlatformHealthItems, getPlatformHealthLevel } from "../features/system/presentation";

export function SystemHealthPage() {
  const healthSummaryQuery = usePlatformHealthSummary();
  const healthSummary = healthSummaryQuery.data;
  const healthItems = healthSummary ? getPlatformHealthItems(healthSummary) : [];
  const healthLevel = healthSummary ? getPlatformHealthLevel(healthSummary) : "down";

  return (
    <AppShell
      eyebrow="平台工具"
      title="系统状态"
      description="系统状态页负责承接健康摘要、关键依赖状态和运行级告警，不演变成监控大屏。"
      actions={
        <div className="action-row">
          <Link className="action-link" to="/system/tasks">
            进入任务中心
          </Link>
        </div>
      }
    >
      <section className="summary-grid" aria-label="系统状态摘要">
        <article className="summary-card summary-card-emphasis">
          <p className="card-label">当前状态</p>
          <h2>
            {healthSummaryQuery.isLoading
              ? "健康摘要加载中"
              : healthSummaryQuery.isError
                ? "健康摘要加载失败"
                : "健康摘要已接入"}
          </h2>
          <p className={`status-pill status-pill-${healthLevel}`}>
            {healthSummaryQuery.isLoading ? "loading" : healthLevel}
          </p>
          <p className="card-copy">
            页面真实消费 `/api/v1/platform/health/summary`，只展示 API、Database、Worker、Scheduler 和附加说明。
          </p>
          {healthSummaryQuery.isError ? (
            <p className="card-copy">当前无法读取健康摘要接口，请稍后重试。</p>
          ) : null}
        </article>

        {healthItems.map((item) => (
          <article key={item.key} className="summary-card">
            <p className="card-label">组件状态</p>
            <h2>{item.label}</h2>
            <p className={`status-pill status-pill-${item.value}`}>{item.value}</p>
            <p className="card-copy">当前组件状态由健康摘要接口返回，不在前端额外推断业务数据。</p>
          </article>
        ))}

        <article className="summary-card">
          <p className="card-label">运行说明</p>
          <h2>Notes</h2>
          {healthSummaryQuery.isLoading ? <p className="card-copy">正在加载运行说明…</p> : null}
          {healthSummary && healthSummary.notes.length > 0 ? (
            <ul className="health-note-list">
              {healthSummary.notes.map((note) => (
                <li key={note} className="health-note-item">
                  {note}
                </li>
              ))}
            </ul>
          ) : null}
          {healthSummary && healthSummary.notes.length === 0 ? (
            <p className="card-copy">当前没有额外的运行级说明。</p>
          ) : null}
        </article>
      </section>
    </AppShell>
  );
}
