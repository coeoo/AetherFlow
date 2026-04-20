import { Link } from "react-router-dom";

import {
  formatCveRelativeTime,
  getCvePhaseLabel,
  getCveStopReasonLabel,
} from "../presentation";
import type { CVERunDetail, CVERunListItem } from "../types";
import { CVERunHistoryList } from "./CVERunHistoryList";

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

function getStatusCopy(
  loadingResult: boolean,
  detail: CVERunDetail | null,
  resultSource: ResultSource,
) {
  if (loadingResult && !detail) {
    return "正在查询该编号最近一次可用结果。";
  }
  if (!detail) {
    return "当前没有历史结果，可立即开始一次 Patch 检索。";
  }
  if (resultSource === "fresh") {
    return detail.progress.terminal
      ? "已展示最新检索结果"
      : "当前正在展示这次重新检索的运行状态。";
  }
  if (resultSource === "history") {
    return "已展示该编号最近一次 Patch 检索结果";
  }
  return "已展示当前记录。";
}

function getStatusLabel(loadingResult: boolean, detail: CVERunDetail | null) {
  if (loadingResult && !detail) {
    return "读取中";
  }
  if (!detail) {
    return "等待中";
  }
  if (detail.status === "queued") {
    return "排队中";
  }
  if (detail.status === "running") {
    return detail.progress.status_label ?? "运行中";
  }
  if (detail.status === "succeeded") {
    return "已完成";
  }
  return "已失败";
}

function getProgressPercent(detail: CVERunDetail) {
  if (typeof detail.progress.percent === "number") {
    return Math.max(0, Math.min(100, detail.progress.percent));
  }

  return Math.round(
    (detail.progress.completed_steps / Math.max(detail.progress.total_steps, 1)) * 100,
  );
}

function getVisitedTraceCount(detail: CVERunDetail) {
  return detail.progress.visited_trace_count ?? detail.source_traces.length;
}

function getDownloadedPatchCount(detail: CVERunDetail) {
  if (typeof detail.progress.downloaded_patch_count === "number") {
    return detail.progress.downloaded_patch_count;
  }

  return detail.patches.filter((patch) => patch.download_status === "downloaded").length;
}

function getFailedTraceCount(detail: CVERunDetail) {
  if (typeof detail.progress.failed_trace_count === "number") {
    return detail.progress.failed_trace_count;
  }

  return detail.source_traces.filter((trace) => trace.status === "failed").length;
}

function getRecentTraces(detail: CVERunDetail) {
  return [...detail.source_traces].slice(-3).reverse();
}

function getOverviewHeadline(detail: CVERunDetail) {
  if (detail.summary.patch_found) {
    return "当前已经命中可复查的补丁结果。";
  }
  if (detail.status === "failed") {
    return "这次运行已经失败，建议进入详情页排查失败步骤和原始轨迹。";
  }
  if (detail.status === "queued") {
    return "任务仍在排队，当前还没有生成页面轨迹和补丁结果。";
  }
  return "当前运行仍在推进，详细的 patch、trace 和 diff 统一放在详情页查看。";
}

function getPrimaryEvidenceCopy(detail: CVERunDetail) {
  return detail.summary.primary_patch_url ?? "尚未形成主证据";
}

export function PatchLookupResultPage({
  query,
  detail,
  historyRuns,
  resultSource,
  loadingResult,
  isRefreshing: _isRefreshing,
  canStartRun,
  onStartRun,
  selectedPatchId: _selectedPatchId,
  onSelectPatch: _onSelectPatch,
  patchContent: _patchContent,
  patchLoading: _patchLoading,
  patchErrorMessage: _patchErrorMessage,
}: Props) {
  const recentTraces = detail ? getRecentTraces(detail) : [];
  const showLivePanel = Boolean(
    detail &&
      !detail.progress.terminal &&
      (detail.status === "running" || getVisitedTraceCount(detail) > 0),
  );
  const lastUpdatedCopy = detail
    ? formatCveRelativeTime(detail.progress.last_updated_at)
    : null;

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
              {getStatusCopy(loadingResult, detail, resultSource)}
            </p>
          </div>

          <div className="patch-status-side">
            <p className={`status-pill status-pill-${detail?.status ?? "running"}`}>
              {getStatusLabel(loadingResult, detail)}
            </p>
            {!detail ? (
              <div className="patch-empty-state">
                <p className="card-copy">
                  当前仅支持使用 <strong>漏洞编号</strong> 作为 Patch 检索入口。若该编号还没有历史结果，可以立即发起一次新的检索。
                </p>
                <div className="action-row">
                  <button
                    className="action-link action-link-obsidian"
                    disabled={!canStartRun}
                    onClick={onStartRun}
                    type="button"
                  >
                    开始检索
                  </button>
                </div>
              </div>
            ) : (
              <div className="action-row">
                <button
                  className="action-link action-link-obsidian"
                  disabled={!canStartRun}
                  onClick={onStartRun}
                  type="button"
                >
                  重新检索
                </button>
                <Link
                  className="action-link action-link-muted"
                  to={`/patch/runs/${detail.run_id}`}
                >
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
        <section className="patch-workbench-grid">
          {showLivePanel ? (
            <section
              className="cve-panel cve-panel-featured patch-live-panel"
              data-testid="patch-live-panel"
            >
              <div className="patch-live-panel-header">
                <div className="cve-panel-header">
                  <p className="card-label">运行中反馈</p>
                  <h3>后台仍在执行</h3>
                  <p className="card-copy">
                    {detail.progress.latest_signal ??
                      "当前运行仍在推进，下面会持续刷新最近动作和抓取内容。"}
                  </p>
                </div>
                <p className={`status-pill status-pill-${detail.status}`}>
                  {detail.progress.status_label ?? "运行中"}
                </p>
              </div>

              <div className="patch-live-progress-block">
                <div className="patch-live-progress-meta">
                  <strong>{getProgressPercent(detail)}%</strong>
                  <span>
                    当前阶段：{getCvePhaseLabel(detail.phase)}
                    {lastUpdatedCopy ? ` · 最近更新：${lastUpdatedCopy}` : ""}
                  </span>
                </div>
                <div aria-hidden="true" className="patch-live-progress-track">
                  <div
                    className="patch-live-progress-bar"
                    style={{ width: `${getProgressPercent(detail)}%` }}
                  />
                </div>
              </div>

              <div className="patch-live-stat-grid">
                <article className="summary-inline-item">
                  <strong>已抓取页面</strong>
                  <span>{getVisitedTraceCount(detail)}</span>
                </article>
                <article className="summary-inline-item">
                  <strong>已下载 patch</strong>
                  <span>{getDownloadedPatchCount(detail)}</span>
                </article>
                <article className="summary-inline-item">
                  <strong>失败抓取</strong>
                  <span>{getFailedTraceCount(detail)}</span>
                </article>
                <article className="summary-inline-item">
                  <strong>执行进度</strong>
                  <span>
                    {detail.progress.completed_steps}/{detail.progress.total_steps}
                  </span>
                </article>
              </div>
            </section>
          ) : null}

          <section className="cve-panel patch-current-overview-panel">
            <div className="cve-panel-header">
              <p className="card-label">当前结果概览</p>
              <h3>当前结果概览</h3>
            </div>
            <p className="card-copy">{getOverviewHeadline(detail)}</p>
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
                <strong>主证据</strong>
                <span>{getPrimaryEvidenceCopy(detail)}</span>
              </article>
              <article className="summary-inline-item">
                <strong>patch 候选</strong>
                <span>{detail.summary.patch_count ?? detail.patches.length}</span>
              </article>
              <article className="summary-inline-item">
                <strong>运行编号</strong>
                <span>{detail.run_id}</span>
              </article>
            </div>

            {detail.recent_progress.length ? (
              <section className="patch-recent-activity-panel">
                <div className="cve-panel-header">
                  <p className="card-label">最近动作</p>
                  <h3>最近动作</h3>
                </div>
                <div className="patch-progress-list">
                  {detail.recent_progress
                    .slice()
                    .reverse()
                    .map((progress, index) => (
                      <article
                        key={`${detail.run_id}-${progress.step}-${progress.status}-${index}`}
                        className="summary-inline-item"
                      >
                        <strong>{progress.label}</strong>
                        <span className={`cve-status-chip cve-status-chip-${progress.status}`}>
                          {progress.status}
                        </span>
                        {progress.detail ? <span>{progress.detail}</span> : null}
                        {progress.error_message ? (
                          <span className="cve-error-copy">{progress.error_message}</span>
                        ) : null}
                      </article>
                    ))}
                </div>
              </section>
            ) : null}

            {showLivePanel && recentTraces.length ? (
              <section className="patch-recent-trace-panel">
                <div className="cve-panel-header">
                  <p className="card-label">最近抓取内容</p>
                  <h3>最近抓取内容</h3>
                </div>
                <div className="cve-trace-list">
                  {recentTraces.map((trace) => (
                    <article
                      key={trace.fetch_id}
                      className={`cve-trace-item${
                        trace.status === "failed" ? " cve-trace-item-failed" : ""
                      }`}
                    >
                      <div className="cve-trace-title-row">
                        <strong>{trace.label}</strong>
                        <span className={`cve-status-chip cve-status-chip-${trace.status}`}>
                          {trace.status}
                        </span>
                      </div>
                      <p className="card-copy">{trace.url ?? trace.source_ref ?? "无可展示 URL"}</p>
                      {trace.error_message ? (
                        <p className="cve-error-copy">{trace.error_message}</p>
                      ) : null}
                    </article>
                  ))}
                </div>
              </section>
            ) : null}
          </section>

          <section className="patch-history-preview">
            <CVERunHistoryList runs={historyRuns} />
          </section>
        </section>
      ) : null}
    </section>
  );
}
