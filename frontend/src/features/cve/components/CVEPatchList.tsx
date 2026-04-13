import type { CVEPatch } from "../types";

type Props = {
  patches: CVEPatch[];
  selectedCandidateUrl: string | null;
  onSelect: (candidateUrl: string) => void;
};

export function CVEPatchList({ patches, selectedCandidateUrl, onSelect }: Props) {
  return (
    <section className="cve-panel">
      <div className="cve-panel-header">
        <p className="card-label">Patch 列表</p>
        <h3>候选与下载结果</h3>
      </div>
      <div className="cve-patch-list">
        {patches.map((patch, index) => (
          <article
            key={patch.artifact_id ?? `${patch.candidate_url}:${patch.patch_type}:${index}`}
            className="cve-patch-item"
          >
            <div className="cve-trace-title-row">
              <strong>{patch.patch_type.toUpperCase()}</strong>
              <span className={`cve-status-chip cve-status-chip-${patch.download_status}`}>{patch.download_status}</span>
            </div>
            <p className="card-copy">{patch.candidate_url}</p>
            {patch.duplicate_count > 1 ? <p className="card-copy">共 {patch.duplicate_count} 条记录</p> : null}
            <div className="action-row">
              <button
                className="cve-inline-button"
                disabled={!patch.content_available}
                onClick={() => onSelect(patch.candidate_url)}
                type="button"
              >
                {selectedCandidateUrl === patch.candidate_url ? "查看中" : "查看 Diff"}
              </button>
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}
