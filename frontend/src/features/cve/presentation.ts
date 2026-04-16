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

const PATCH_TYPE_LABELS: Record<string, string> = {
  patch: "Patch",
  diff: "Diff",
  debdiff: "Debdiff",
  github_commit_patch: "GitHub Commit Patch",
  github_pull_patch: "GitHub PR Patch",
  gitlab_commit_patch: "GitLab Commit Patch",
  gitlab_merge_request_patch: "GitLab MR Patch",
  kernel_commit_patch: "Kernel Commit Patch",
  bugzilla_attachment_patch: "Bugzilla Attachment Patch",
};

const STOP_REASON_ADVICE: Record<string, string> = {
  no_seed_references: "建议先检查当前 CVE 是否存在可用参考链接，再确认是否需要补充其他来源。",
  fetch_failed: "建议先检查目标页面是否仍可访问，再确认是否需要补抓或更换来源。",
  no_patch_candidates: "建议先回看已探索页面，再确认规则是否漏掉了补丁入口。",
  patch_download_failed: "建议先检查补丁地址是否仍有效，再确认内容是否还是可下载的 patch/diff。",
  resolve_seeds_failed: "建议先检查参考链接解析结果，再确认上游数据源是否稳定。",
  plan_frontier_failed: "建议先检查页面规划输入是否完整，再确认探索规则是否需要收紧。",
  analyze_page_failed: "建议先回看页面正文与命中规则，再确认分析逻辑是否遗漏边界情况。",
  download_patches_failed: "建议先检查下载链路和内容校验，再确认候选 patch 是否真实可读。",
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

export function getCvePatchTypeLabel(patchType: string) {
  return PATCH_TYPE_LABELS[patchType] ?? patchType;
}

export function getCveFailureAdvice(stopReason: string | null) {
  if (!stopReason) {
    return null;
  }

  return STOP_REASON_ADVICE[stopReason] ?? "建议先检查失败步骤对应的来源、响应和错误信息。";
}

export function getCveTraceHeadline(hasFailedTrace: boolean) {
  return hasFailedTrace ? "最近失败步骤" : "探索过的关键页面";
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

export function getCveHistorySourceSummary(summary: {
  primary_family_source_host?: string;
  primary_family_evidence_source_count?: number;
} | null | undefined) {
  const sourceHost = summary?.primary_family_source_host?.trim();
  if (!sourceHost) {
    return null;
  }

  const evidenceSourceCount = summary?.primary_family_evidence_source_count ?? 0;
  if (evidenceSourceCount > 1) {
    return `来源：${sourceHost} 等 ${evidenceSourceCount} 个关联来源`;
  }

  return `来源：${sourceHost}`;
}
