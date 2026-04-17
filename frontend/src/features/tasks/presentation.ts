import type { PlatformTaskDetailView, PlatformTaskListItemView } from "./types";

export function getTaskPrimaryCopy(task: PlatformTaskListItemView | PlatformTaskDetailView) {
  if (task.scene_name === "cve") {
    return String(task.payload_summary.cve_id ?? task.job_id);
  }

  if (typeof task.payload_summary.source_url === "string") {
    return String(task.payload_summary.source_url);
  }

  if (typeof task.payload_summary.source_id === "string") {
    return `source_id=${task.payload_summary.source_id}`;
  }

  return task.job_id;
}

export function getTaskRunLink(task: PlatformTaskListItemView | PlatformTaskDetailView) {
  if (!task.scene_run_id) {
    return null;
  }
  if (task.scene_name === "cve") {
    return `/patch/runs/${task.scene_run_id}`;
  }
  if (task.scene_name === "announcement") {
    return `/announcements/runs/${task.scene_run_id}`;
  }
  return null;
}
