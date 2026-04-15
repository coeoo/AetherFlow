import type { CVESourceTrace } from "../types";
import { getCveTraceHeadline } from "../presentation";

type Props = {
  traces: CVESourceTrace[];
};

export function CVETraceTimeline({ traces }: Props) {
  const hasFailedTrace = traces.some((trace) => trace.status === "failed");

  return (
    <section className="cve-panel">
      <div className="cve-panel-header">
        <p className="card-label">Trace 时间线</p>
        <h3>{getCveTraceHeadline(hasFailedTrace)}</h3>
      </div>
      <div className="cve-trace-list">
        {traces.map((trace) => (
          <article
            key={trace.fetch_id}
            className={`cve-trace-item${trace.status === "failed" ? " cve-trace-item-failed" : ""}`}
          >
            <div className="cve-trace-title-row">
              <strong>{trace.label}</strong>
              <span className={`cve-status-chip cve-status-chip-${trace.status}`}>{trace.status}</span>
            </div>
            <p className="card-copy">{trace.url ?? trace.source_ref ?? "无可展示 URL"}</p>
            {trace.error_message ? <p className="cve-error-copy">{trace.error_message}</p> : null}
          </article>
        ))}
      </div>
    </section>
  );
}
