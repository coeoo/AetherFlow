import { Link } from "react-router-dom";

import {
  formatCveRunCreatedAt,
  getCveHistorySourceSummary,
  getCvePhaseLabel,
  getCveStopReasonLabel,
} from "../presentation";
import type { CVERunListItem } from "../types";

type Props = {
  runs: CVERunListItem[];
};

export function CVERunHistoryList({ runs }: Props) {
  return (
    <section className="cve-panel cve-history-panel">
      <div className="cve-panel-header">
        <p className="card-label">最近运行</p>
        <h2>回看刚刚跑过的结论</h2>
      </div>
      <div className="cve-history-list">
        {runs.length ? (
          runs.map((run) => {
            const sourceSummary = getCveHistorySourceSummary(run.summary);
            return (
              <article key={run.run_id} className="cve-history-item">
                <div className="cve-trace-title-row">
                  <strong>{run.cve_id}</strong>
                  <span className={`cve-status-chip cve-status-chip-${run.status}`}>{run.status}</span>
                </div>
                <p className="card-copy">阶段：{getCvePhaseLabel(run.phase)}</p>
                <p className="card-copy">
                  结论：{run.summary.primary_patch_url ?? getCveStopReasonLabel(run.stop_reason, run.status)}
                </p>
                {sourceSummary ? <p className="card-copy">{sourceSummary}</p> : null}
                <div className="cve-history-footer">
                  <span className="card-label">{formatCveRunCreatedAt(run.created_at)}</span>
                  <Link className="action-link action-link-muted" to={`/cve/runs/${run.run_id}`}>
                    查看详情
                  </Link>
                </div>
              </article>
            );
          })
        ) : (
          <p className="card-copy">当前还没有可回看的运行记录，先发起一次检索。</p>
        )}
      </div>
    </section>
  );
}
