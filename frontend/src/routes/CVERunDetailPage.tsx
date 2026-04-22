import { Link, useParams } from "react-router-dom";
import { useState } from "react";

import { AppShell } from "../components/layout/AppShell";
import { CVEBudgetPanel } from "../features/cve/components/CVEBudgetPanel";
import { CVEChainTracker } from "../features/cve/components/CVEChainTracker";
import { CVEDiffViewer } from "../features/cve/components/CVEDiffViewer";
import { CVEFixFamilySummary } from "../features/cve/components/CVEFixFamilySummary";
import { CVEPatchList } from "../features/cve/components/CVEPatchList";
import { CVESearchGraphPanel } from "../features/cve/components/CVESearchGraphPanel";
import { CVETraceTimeline } from "../features/cve/components/CVETraceTimeline";
import { CVEVerdictHero } from "../features/cve/components/CVEVerdictHero";
import { useCveRunDetail, usePatchContent } from "../features/cve/hooks";
import { getCvePhaseLabel, getCveStopReasonLabel } from "../features/cve/presentation";

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

  const hasEvidencePayload = detail.source_traces.length > 0 || detail.patches.length > 0;
  const hasAgentChains = Boolean(detail.summary.chain_summary && detail.summary.chain_summary.length > 0);
  const hasSearchGraph = Boolean(detail.search_graph && detail.search_graph.nodes.length > 0);

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

      <section className="cve-panel">
        <div className="cve-panel-header">
          <p className="card-label">当前运行状态</p>
          <h2>先确认这条 run 目前走到了哪里</h2>
        </div>
        <div className="summary-grid patch-summary-grid">
          <article className="summary-inline-item">
            <strong>状态</strong>
            <span>{detail.status}</span>
          </article>
          <article className="summary-inline-item">
            <strong>阶段</strong>
            <span>{getCvePhaseLabel(detail.phase)}</span>
          </article>
          <article className="summary-inline-item">
            <strong>停止原因</strong>
            <span>{getCveStopReasonLabel(detail.stop_reason, detail.status)}</span>
          </article>
          <article className="summary-inline-item">
            <strong>执行进度</strong>
            <span>
              {detail.progress.completed_steps}/{detail.progress.total_steps}
            </span>
          </article>
        </div>
        {!hasEvidencePayload ? (
          <p className="card-copy">
            当前这条 run 还没有生成页面轨迹或补丁结果。若状态仍是 queued/running，说明任务还没推进到可展示阶段；如果长时间停留不动，请先检查 worker 是否正常消费任务。
          </p>
        ) : null}
      </section>

      {hasAgentChains ? <CVEChainTracker chains={detail.summary.chain_summary ?? []} /> : null}
      {detail.summary.budget_usage ? <CVEBudgetPanel budget={detail.summary.budget_usage} /> : null}
      {hasSearchGraph ? (
        <CVESearchGraphPanel
          nodes={detail.search_graph?.nodes ?? []}
          edges={detail.search_graph?.edges ?? []}
          decisions={detail.decision_history ?? []}
          frontierStatus={detail.frontier_status}
        />
      ) : null}

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
