import { Link, useParams } from "react-router-dom";
import { useState } from "react";

import { AppShell } from "../components/layout/AppShell";
import { CVEDiffViewer } from "../features/cve/components/CVEDiffViewer";
import { CVEFixFamilySummary } from "../features/cve/components/CVEFixFamilySummary";
import { CVEPatchList } from "../features/cve/components/CVEPatchList";
import { CVETraceTimeline } from "../features/cve/components/CVETraceTimeline";
import { CVEVerdictHero } from "../features/cve/components/CVEVerdictHero";
import { useCveRunDetail, usePatchContent } from "../features/cve/hooks";

export function CVERunDetailPage() {
  const { runId = "未提供 runId" } = useParams();
  const [selectedPatchId, setSelectedPatchId] = useState<string | null>(null);
  const detailQuery = useCveRunDetail(runId);
  const patchContentQuery = usePatchContent(runId, selectedPatchId);
  const detail = detailQuery.data;

  if (detailQuery.isLoading) {
    return (
      <AppShell
        eyebrow="Patch 检索"
        title="Patch 运行详情"
        description={`正在加载 run_id = ${runId} 的证据页内容。`}
        actions={
          <div className="action-row">
            <Link className="action-link action-link-muted" to="/patch">
              返回 Patch 检索
            </Link>
          </div>
        }
      >
        <section className="cve-panel">
          <p className="card-copy">正在加载运行详情…</p>
        </section>
      </AppShell>
    );
  }

  if (!detail) {
    return (
      <AppShell
        eyebrow="Patch 检索"
        title="Patch 运行详情"
        description={`run_id = ${runId} 的详情暂不可用。`}
        actions={
          <div className="action-row">
            <Link className="action-link action-link-muted" to="/patch">
              返回 Patch 检索
            </Link>
          </div>
        }
      >
        <section className="cve-panel">
          <p className="cve-error-copy">详情加载失败，请稍后重试。</p>
        </section>
      </AppShell>
    );
  }

  return (
    <AppShell
      eyebrow="Patch 检索"
      title="Patch 运行详情"
      description={`当前正在阅读 run_id = ${runId} 的补丁结论、探索证据与 Diff 内容。`}
      actions={
        <div className="action-row">
          <Link className="action-link action-link-muted" to="/patch">
            返回 Patch 检索
          </Link>
        </div>
      }
    >
      <CVEVerdictHero detail={detail} />

      <section className="cve-detail-grid">
        <div className="cve-detail-main">
          <CVEDiffViewer
            content={patchContentQuery.data?.content ?? null}
            loading={patchContentQuery.isLoading}
            errorMessage={patchContentQuery.error instanceof Error ? patchContentQuery.error.message : null}
          />
        </div>
        <aside className="cve-detail-rail">
          <CVEFixFamilySummary families={detail.fix_families ?? []} />
          <CVEPatchList
            patches={detail.patches}
            selectedPatchId={selectedPatchId}
            onSelect={setSelectedPatchId}
          />
          <CVETraceTimeline traces={detail.source_traces} />
        </aside>
      </section>
    </AppShell>
  );
}
