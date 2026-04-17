import type { CVERunDetail } from "../types";
import {
  getCveFailureAdvice,
  getCveLlmFallbackCopy,
  getCvePhaseLabel,
  getCveStopReasonLabel,
} from "../presentation";

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
  const failureAdvice = detail.status === "failed" ? getCveFailureAdvice(detail.stop_reason) : null;
  const llmFallbackCopy = getCveLlmFallbackCopy(detail.summary);

  return (
    <section className="cve-verdict-hero">
      <div className="cve-verdict-copy">
        <p className="card-label">主补丁证据</p>
        <h2>{getVerdictLabel(detail)}</h2>
        <p className="card-copy">
          当前运行处于 <strong>{getCvePhaseLabel(detail.phase)}</strong>，{detail.summary.patch_count ?? 0} 条 patch 候选已进入结果面。
        </p>
        {failureAdvice ? <p className="card-copy cve-guidance-copy">{failureAdvice}</p> : null}
        {llmFallbackCopy ? (
          <div className="cve-guidance-copy">
            <p className="card-label">受限 LLM 建议</p>
            <p className="card-copy">{llmFallbackCopy}</p>
            {detail.summary.llm_selected_candidate_url ? (
              <p className="card-copy">建议候选：{detail.summary.llm_selected_candidate_url}</p>
            ) : null}
            <p className="card-copy">
              来源：{detail.summary.llm_verdict_source ?? "llm_fallback"} · 模型：
              {detail.summary.llm_model ?? "unknown"}
            </p>
          </div>
        ) : null}
        {detail.summary.error ? <p className="cve-error-copy">错误摘要：{detail.summary.error}</p> : null}
      </div>
      <div className="cve-verdict-meta">
        <div className="cve-kpi-card cve-kpi-card-dark">
          <span className="card-label">主证据</span>
          <strong>{detail.summary.primary_patch_url ?? "尚未形成主证据"}</strong>
        </div>
        <div className="cve-kpi-card">
          <span className="card-label">停止原因</span>
          <strong>{getCveStopReasonLabel(detail.stop_reason, detail.status)}</strong>
        </div>
      </div>
    </section>
  );
}
