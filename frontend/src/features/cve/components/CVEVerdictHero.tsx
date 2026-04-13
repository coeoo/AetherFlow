import type { CVERunDetail } from "../types";

type Props = {
  detail: CVERunDetail;
};

function getVerdictLabel(detail: CVERunDetail) {
  if (detail.summary.patch_found) {
    return "已命中补丁";
  }
  if (detail.status === "failed") {
    return "未命中补丁";
  }
  return "正在探索证据";
}

export function CVEVerdictHero({ detail }: Props) {
  return (
    <section className="cve-verdict-hero">
      <div className="cve-verdict-copy">
        <p className="card-label">主补丁证据</p>
        <h2>{getVerdictLabel(detail)}</h2>
        <p className="card-copy">
          当前运行处于 <strong>{detail.phase}</strong>，{detail.summary.patch_count ?? 0} 条 patch 候选已进入结果面。
        </p>
      </div>
      <div className="cve-verdict-meta">
        <div className="cve-kpi-card cve-kpi-card-dark">
          <span className="card-label">主证据</span>
          <strong>{detail.summary.primary_patch_url ?? "尚未形成主证据"}</strong>
        </div>
        <div className="cve-kpi-card">
          <span className="card-label">停止原因</span>
          <strong>{detail.stop_reason ?? "运行中"}</strong>
        </div>
      </div>
    </section>
  );
}
