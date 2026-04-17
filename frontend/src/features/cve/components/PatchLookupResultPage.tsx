import { Link } from "react-router-dom";

import {
  getCveFailureAdvice,
  getCveLlmFallbackCopy,
  getCvePhaseLabel,
  getCveStopReasonLabel,
} from "../presentation";
import type { CVERunDetail, CVERunListItem } from "../types";
import { CVEDiffViewer } from "./CVEDiffViewer";
import { CVEFixFamilySummary } from "./CVEFixFamilySummary";
import { CVEPatchList } from "./CVEPatchList";
import { CVERunHistoryList } from "./CVERunHistoryList";
import { CVETraceTimeline } from "./CVETraceTimeline";
import { CVEVerdictHero } from "./CVEVerdictHero";

type ResultSource = "history" | "fresh" | null;

type Props = {
  query: string;
  detail: CVERunDetail | null;
  historyRuns: CVERunListItem[];
  resultSource: ResultSource;
  loadingResult: boolean;
  isRefreshing: boolean;
  canStartRun: boolean;
  onStartRun: () => void;
  selectedPatchId: string | null;
  onSelectPatch: (patchId: string) => void;
  patchContent: string | null;
  patchLoading: boolean;
  patchErrorMessage: string | null;
};

function getStatusCopy(resultSource: ResultSource, isRefreshing: boolean) {
  if (isRefreshing) {
    return "正在更新本次 Patch 检索结果";
  }
  if (resultSource === "history") {
    return "已展示该编号最近一次 Patch 检索结果";
  }
  if (resultSource === "fresh") {
    return "已展示最新 Patch 检索结果";
  }
  return "当前没有历史结果，可立即开始一次 Patch 检索。";
}

function getStatusLabel(loadingResult: boolean, detail: CVERunDetail | null, isRefreshing: boolean) {
  if (loadingResult) {
    return "读取中";
  }
  if (isRefreshing) {
    return "更新中";
  }
  if (detail) {
    return "已就绪";
  }
  return "等待中";
}

function buildTrustReason(detail: CVERunDetail) {
  const llmFallbackCopy = getCveLlmFallbackCopy(detail.summary);
  const sourceHost = detail.summary.primary_family_source_host?.trim();
  const evidenceSourceCount = detail.summary.primary_family_evidence_source_count ?? 0;
  const failedTrace = detail.source_traces.find((trace) => trace.status === "failed");

  if (detail.summary.patch_found) {
    if (sourceHost && evidenceSourceCount > 1) {
      return `当前已经形成主补丁结论，主证据来自 ${sourceHost}，并有 ${evidenceSourceCount} 个关联来源共同指向同一修复族。`;
    }
    if (sourceHost) {
      return `当前已经形成主补丁结论，主证据直接落在 ${sourceHost} 提供的 patch 来源上。`;
    }
    if (detail.summary.primary_patch_url) {
      return `当前已经形成主补丁结论，主证据直接落在 ${detail.summary.primary_patch_url}。`;
    }
  }

  if (llmFallbackCopy) {
    return llmFallbackCopy;
  }

  if (detail.status === "failed") {
    const failureHeadline = `本次运行在 ${getCvePhaseLabel(detail.phase)} 阶段停止，停止原因是 ${getCveStopReasonLabel(detail.stop_reason, detail.status)}。`;
    if (failedTrace?.url) {
      return `${failureHeadline} 最近失败来源是 ${failedTrace.url}。`;
    }
    return failureHeadline;
  }

  return `当前运行仍处于 ${getCvePhaseLabel(detail.phase)} 阶段，已汇总 ${detail.summary.patch_count ?? 0} 条 patch 候选，结论仍在收敛。`;
}

function buildNextStep(detail: CVERunDetail) {
  if (detail.summary.patch_found) {
    return "建议先查看主补丁 Diff 与来源链，再进入开发者详情核对 run 元信息和原始页面轨迹。";
  }

  if (detail.status === "failed") {
    return getCveFailureAdvice(detail.stop_reason) ?? "建议先回看失败步骤对应的来源、响应和错误信息，再决定是否重新检索。";
  }

  return "建议先等待当前运行收敛；如果历史结果已经足够，可以直接在右侧最近运行中回看已有结论。";
}

function getRunSummaryHeadline(detail: CVERunDetail) {
  if (detail.summary.patch_found) {
    return "本次运行已经收敛到可复查的主补丁结论。";
  }
  if (detail.status === "failed") {
    return "本次运行没有形成可用补丁，需要回看失败阶段和来源链。";
  }
  return "本次运行仍在持续收敛，当前摘要会随着后续阶段继续刷新。";
}

export function PatchLookupResultPage({
  query,
  detail,
  historyRuns,
  resultSource,
  loadingResult,
  isRefreshing,
  canStartRun,
  onStartRun,
  selectedPatchId,
  onSelectPatch,
  patchContent,
  patchLoading,
  patchErrorMessage,
}: Props) {
  const trustReason = detail ? buildTrustReason(detail) : null;
  const nextStep = detail ? buildNextStep(detail) : null;

  return (
    <section className="patch-page-stack">
      <section className="cve-panel cve-panel-featured patch-status-panel">
        <div className="patch-status-layout">
          <div className="patch-status-copy">
            <div className="cve-panel-header">
              <p className="card-label">当前结果</p>
              <h2>{query || "等待查询对象"}</h2>
            </div>
            <p className="card-copy">
              {loadingResult ? "正在读取该编号最近一次 Patch 检索结果" : getStatusCopy(resultSource, isRefreshing)}
            </p>
          </div>

          <div className="patch-status-side">
            <p className="status-pill status-pill-running">{getStatusLabel(loadingResult, detail, isRefreshing)}</p>
            {!detail ? (
              <div className="patch-empty-state">
                <p className="card-copy">
                  当前仅支持使用 <strong>漏洞编号</strong> 作为 Patch 检索入口。若该编号还没有历史结果，可以立即发起一次新的检索。
                </p>
                <div className="action-row">
                  <button className="action-link action-link-obsidian" disabled={!canStartRun} onClick={onStartRun} type="button">
                    开始检索
                  </button>
                </div>
              </div>
            ) : (
              <div className="action-row">
                <button
                  className="action-link action-link-obsidian"
                  disabled={!canStartRun || isRefreshing}
                  onClick={onStartRun}
                  type="button"
                >
                  {resultSource === "history" ? "重新检索" : "刷新检索"}
                </button>
                <Link className="action-link action-link-muted" to={`/patch/runs/${detail.run_id}`}>
                  查看运行详情
                </Link>
              </div>
            )}
          </div>
        </div>
      </section>

      {!detail && historyRuns.length > 0 ? (
        <section className="patch-history-preview">
          <CVERunHistoryList runs={historyRuns} />
        </section>
      ) : null}

      {detail ? (
        <section className="patch-command-grid">
          <div className="patch-command-main">
            <CVEVerdictHero detail={detail} />

            <section className="patch-narrative-grid">
              <article className="cve-panel patch-narrative-card">
                <div className="cve-panel-header">
                  <p className="card-label">可信原因</p>
                  <h3>为什么当前结论可信</h3>
                </div>
                <p className="card-copy">{trustReason}</p>
              </article>

              <article className="cve-panel patch-narrative-card">
                <div className="cve-panel-header">
                  <p className="card-label">下一步建议</p>
                  <h3>接下来该怎么处理</h3>
                </div>
                <p className="card-copy">{nextStep}</p>
              </article>
            </section>

            <section className="cve-panel patch-run-summary-panel">
              <div className="cve-panel-header">
                <p className="card-label">运行摘要</p>
                <h3>当前结论的收敛情况</h3>
              </div>
              <p className="card-copy">{getRunSummaryHeadline(detail)}</p>
              <div className="summary-grid patch-summary-grid">
                <article className="summary-inline-item">
                  <strong>当前阶段</strong>
                  <span>{getCvePhaseLabel(detail.phase)}</span>
                </article>
                <article className="summary-inline-item">
                  <strong>停止原因</strong>
                  <span>{getCveStopReasonLabel(detail.stop_reason, detail.status)}</span>
                </article>
                <article className="summary-inline-item">
                  <strong>patch 候选</strong>
                  <span>{detail.summary.patch_count ?? detail.patches.length}</span>
                </article>
                <article className="summary-inline-item">
                  <strong>执行进度</strong>
                  <span>
                    {detail.progress.completed_steps}/{detail.progress.total_steps}
                  </span>
                </article>
              </div>
              {detail.recent_progress.length ? (
                <div className="patch-progress-list">
                  {detail.recent_progress.map((progress) => (
                    <article key={`${detail.run_id}-${progress.step}-${progress.status}`} className="summary-inline-item">
                      <strong>{progress.label}</strong>
                      <span>{progress.status}</span>
                      {progress.detail ? <span>{progress.detail}</span> : null}
                    </article>
                  ))}
                </div>
              ) : null}
            </section>

            <section className="cve-panel">
              <div className="cve-panel-header">
                <p className="card-label">主补丁摘要</p>
                <h3>{detail.summary.patch_found ? "已命中补丁" : "未命中补丁"}</h3>
              </div>
              <div className="summary-grid patch-summary-grid">
                <article className="summary-inline-item">
                  <strong>主证据</strong>
                  <span>{detail.summary.primary_patch_url ?? "当前没有可信的主补丁链接"}</span>
                </article>
                <article className="summary-inline-item">
                  <strong>来源主机</strong>
                  <span>{detail.summary.primary_family_source_host ?? "尚未归并到稳定来源"}</span>
                </article>
                <article className="summary-inline-item">
                  <strong>关联来源</strong>
                  <span>{detail.summary.primary_family_evidence_source_count ?? 0} 个</span>
                </article>
                <article className="summary-inline-item">
                  <strong>运行编号</strong>
                  <span>{detail.run_id}</span>
                </article>
              </div>
            </section>

            <section className="patch-detail-surface">
              <CVETraceTimeline traces={detail.source_traces} />
              <CVEDiffViewer
                content={patchContent}
                loading={patchLoading}
                errorMessage={patchErrorMessage}
              />
            </section>
          </div>

          <aside className="patch-command-rail">
            <section className="cve-panel patch-side-status-card">
              <div className="cve-panel-header">
                <p className="card-label">当前状态</p>
                <h3>结果中心</h3>
              </div>
              <div className="patch-side-status-grid">
                <article className="summary-inline-item">
                  <strong>状态</strong>
                  <span>{detail.status}</span>
                </article>
                <article className="summary-inline-item">
                  <strong>阶段</strong>
                  <span>{getCvePhaseLabel(detail.phase)}</span>
                </article>
                <article className="summary-inline-item">
                  <strong>主证据</strong>
                  <span>{detail.summary.primary_patch_url ?? "尚未形成主证据"}</span>
                </article>
              </div>
            </section>

            <CVERunHistoryList runs={historyRuns} />
            <CVEFixFamilySummary families={detail.fix_families} />
            <CVEPatchList
              patches={detail.patches}
              selectedPatchId={selectedPatchId}
              onSelect={onSelectPatch}
            />

            <section className="cve-panel patch-developer-panel" id="developer-details">
              <div className="cve-panel-header">
                <p className="card-label">工程下钻</p>
                <h3>开发者详情</h3>
              </div>
              <div className="patch-developer-sections">
                <details className="patch-developer-disclosure" open>
                  <summary>运行元信息</summary>
                  <div className="patch-developer-grid">
                    <article className="summary-inline-item">
                      <strong>run_id</strong>
                      <span>{detail.run_id}</span>
                    </article>
                    <article className="summary-inline-item">
                      <strong>cve_id</strong>
                      <span>{detail.cve_id}</span>
                    </article>
                    <article className="summary-inline-item">
                      <strong>status</strong>
                      <span>{detail.status}</span>
                    </article>
                    <article className="summary-inline-item">
                      <strong>phase</strong>
                      <span>{detail.phase}</span>
                    </article>
                  </div>
                </details>

                <details className="patch-developer-disclosure">
                  <summary>原始页面轨迹</summary>
                  <CVETraceTimeline traces={detail.source_traces} />
                </details>

                <details className="patch-developer-disclosure">
                  <summary>补丁原始数据</summary>
                  <CVEPatchList
                    patches={detail.patches}
                    selectedPatchId={selectedPatchId}
                    onSelect={onSelectPatch}
                  />
                </details>
              </div>
            </section>
          </aside>
        </section>
      ) : null}
    </section>
  );
}
