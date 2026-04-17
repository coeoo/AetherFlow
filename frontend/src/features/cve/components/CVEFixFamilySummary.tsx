import { getCvePatchTypeLabel } from "../presentation";
import type { CVEFixFamily } from "../types";

type Props = {
  families: CVEFixFamily[];
};

export function CVEFixFamilySummary({ families }: Props) {
  if (families.length === 0) {
    return null;
  }

  return (
    <section className="cve-panel">
      <div className="cve-panel-header">
        <p className="card-label">Fix Family</p>
        <h3>来源家族概览</h3>
      </div>
      <div className="cve-patch-list">
        {families.map((family) => (
          <article key={family.family_key} className="cve-patch-item">
            <div className="cve-trace-title-row">
              <strong>{family.title}</strong>
              <span className="cve-status-chip cve-status-chip-succeeded">{family.discovery_rule}</span>
            </div>
            <p className="card-copy">{family.source_url}</p>
            <p className="card-copy">包含 {family.patch_count} 条候选补丁</p>
            <p className="card-copy">已下载 {family.downloaded_patch_count} 条</p>
            {family.evidence_source_count > 1 ? (
              <p className="card-copy">
                另有 {family.evidence_source_count - 1} 个关联来源共同指向该 fix
              </p>
            ) : null}
            <p className="card-copy">
              类型：{family.patch_types.map((patchType) => getCvePatchTypeLabel(patchType)).join(" / ")}
            </p>
            {family.evidence_sources.length > 1 ? (
              <div className="card-copy">
                {family.evidence_sources.slice(1).map((source) => (
                  <p key={`${family.family_key}-${source.source_url}`}>{source.source_url}</p>
                ))}
              </div>
            ) : null}
          </article>
        ))}
      </div>
    </section>
  );
}
