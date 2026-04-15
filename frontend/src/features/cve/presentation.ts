const STOP_REASON_LABELS: Record<string, string> = {
  patches_downloaded: "已下载补丁",
  no_seed_references: "未找到可用参考链接",
  fetch_failed: "抓取页面失败",
  no_patch_candidates: "未发现补丁候选",
  patch_download_failed: "补丁下载失败",
  resolve_seeds_failed: "参考链接解析失败",
  plan_frontier_failed: "页面探索规划失败",
  analyze_page_failed: "页面分析失败",
  download_patches_failed: "补丁下载阶段失败",
};

const PHASE_LABELS: Record<string, string> = {
  resolve_seeds: "解析参考链接",
  plan_frontier: "规划探索页面",
  fetch_page: "抓取页面",
  analyze_page: "分析页面",
  download_patches: "下载补丁",
  finalize_run: "收敛结果",
};

export function getCveStopReasonLabel(stopReason: string | null, status: string) {
  if (!stopReason) {
    return status === "failed" ? "运行失败" : "运行中";
  }

  return STOP_REASON_LABELS[stopReason] ?? stopReason;
}

export function getCvePhaseLabel(phase: string) {
  return PHASE_LABELS[phase] ?? phase;
}

export function formatCveRunCreatedAt(createdAt: string) {
  const date = new Date(createdAt);
  if (Number.isNaN(date.getTime())) {
    return createdAt;
  }

  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  }).format(date);
}
