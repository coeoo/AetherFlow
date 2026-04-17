import type { SceneEntryCardView } from "./types";
import type { PlatformTaskListItemView } from "../tasks/types";

export function getSceneActionLabel(scene: SceneEntryCardView) {
  return scene.scene_name === "cve" ? "进入 CVE 补丁检索" : "进入安全公告提取";
}

export function getRecentJobTitle(job: PlatformTaskListItemView) {
  if (job.scene_name === "cve") {
    return String(job.payload_summary.cve_id ?? job.job_id);
  }

  return String(job.payload_summary.source_url ?? job.job_id);
}
