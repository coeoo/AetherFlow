import { Link, useParams } from "react-router-dom";
import { AppShell } from "../components/layout/AppShell";

import {
  useAnnouncementRunDetail,
  useCreateAnnouncementRunDeliveries,
} from "../features/announcements/hooks";

export function AnnouncementRunDetailPage() {
  const { runId = "未提供 runId" } = useParams();
  const detailQuery = useAnnouncementRunDetail(runId);
  const createDeliveries = useCreateAnnouncementRunDeliveries(runId);
  const detail = detailQuery.data;
  const delivery = detail?.delivery;

  if (detailQuery.isLoading) {
    return (
      <AppShell
        eyebrow="公告结果页"
        title="安全公告情报包详情"
        description={`正在加载 run_id = ${runId} 的情报包详情。`}
      >
        <section className="cve-panel">
          <p className="card-copy">正在加载运行详情…</p>
        </section>
      </AppShell>
    );
  }

  return (
    <AppShell
      eyebrow="公告结果页"
      title="安全公告情报包详情"
      description={`当前详情页展示 run_id = ${runId} 的最小结构化结果。`}
      actions={
        <div className="action-row">
          <Link className="action-link" to="/announcements">
            返回工作台
          </Link>
          <Link className="action-link action-link-muted" to={`/announcements/runs/${runId}#delivery`}>
            跳到投递区块
          </Link>
        </div>
      }
    >
      <section className="cve-workbench-grid">
        <section className="cve-panel cve-panel-featured">
          <div className="cve-panel-header">
            <p className="card-label">主摘要</p>
            <h2>{detail?.document?.title ?? "公告标题缺失"}</h2>
          </div>
          <p className={`status-pill status-pill-${detail?.status ?? "queued"}`}>{detail?.status ?? "unknown"}</p>
          <p className="card-copy">
            来源：<span>{detail?.document?.source_name ?? "未生成"}</span>
          </p>
          <p className="card-copy">阶段：{detail?.stage ?? "unknown"}</p>
          <p className="card-copy">{detail?.package?.analyst_summary ?? "当前没有分析师摘要。"}</p>
        </section>

        <section className="cve-panel">
          <div className="cve-panel-header">
            <p className="card-label">情报包</p>
            <h2>结构化结果</h2>
          </div>
          <p className="card-copy">置信度：{detail?.package?.confidence?.toFixed(2) ?? "0.00"}</p>
          <p className="card-copy">风险级别：{detail?.package?.severity ?? "未标记"}</p>
          <p className="card-copy">
            投递建议：{detail?.package?.notify_recommended ? "建议投递" : "暂不建议投递"}
          </p>
          <p className="card-copy">原始链接：{detail?.document?.source_url ?? "无"}</p>
        </section>

        <section className="cve-panel">
          <div className="cve-panel-header">
            <p className="card-label">原文摘要</p>
            <h2>正文片段</h2>
          </div>
          <p className="card-copy">{detail?.document?.content_excerpt ?? "当前没有正文片段。"}</p>
        </section>

        <section className="cve-panel" id="delivery">
          <div className="cve-panel-header">
            <p className="card-label">投递区块</p>
            <h2>投递建议与记录</h2>
          </div>
          <p className="card-copy">
            是否建议投递：{delivery?.notify_recommended ? "建议投递" : "暂不建议投递"}
          </p>
          {delivery?.skip_reason ? <p className="card-copy">{delivery.skip_reason}</p> : null}

          <div className="cve-panel-header">
            <p className="card-label">匹配目标</p>
            <h2>推荐列表</h2>
          </div>
          {delivery?.matched_targets.length ? (
            delivery.matched_targets.map((target) => (
              <article key={target.target_id} className="cve-inline-progress">
                <strong>{target.name}</strong>
                <span>
                  {target.channel_type} · {target.match_reason}
                </span>
              </article>
            ))
          ) : (
            <p className="card-copy">当前还没有匹配到可用目标。</p>
          )}

          <div className="action-row">
            <button
              className="action-link action-link-obsidian"
              disabled={
                createDeliveries.isPending ||
                !delivery?.notify_recommended ||
                !delivery?.matched_targets.length
              }
              type="button"
              onClick={() => {
                createDeliveries.mutate();
              }}
            >
              {createDeliveries.isPending ? "生成中…" : "生成投递记录"}
            </button>
            <Link className="action-link action-link-muted" to="/deliveries?tab=records">
              进入投递中心
            </Link>
          </div>

          {createDeliveries.data ? (
            <p className="card-copy">已生成 {createDeliveries.data.created_count} 条投递记录</p>
          ) : null}

          <div className="cve-panel-header">
            <p className="card-label">最近记录</p>
            <h2>平台内留痕</h2>
          </div>
          {delivery?.recent_records.length ? (
            delivery.recent_records.map((record) => (
              <article key={record.record_id} className="cve-inline-progress">
                <strong>{record.target_name}</strong>
                <span>
                  {record.status} · {String(record.payload_summary.title ?? "未命名投递")}
                </span>
              </article>
            ))
          ) : (
            <p className="card-copy">当前还没有投递记录。</p>
          )}
        </section>
      </section>
    </AppShell>
  );
}
