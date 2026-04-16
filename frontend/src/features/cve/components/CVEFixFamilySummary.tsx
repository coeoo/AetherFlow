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
            <p className="card-copy">
              类型：{family.patch_types.map((patchType) => getCvePatchTypeLabel(patchType)).join(" / ")}
            </p>
          </article>
        ))}
      </div>
    </section>
  );
}
