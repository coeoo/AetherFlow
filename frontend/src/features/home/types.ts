import type { DeliveryRecordView } from "../deliveries/types";
import type { PlatformHealthSummary } from "../system/types";
import type { PlatformTaskListItemView } from "../tasks/types";

export type SceneEntryCardView = {
  scene_name: "cve" | "announcement";
  title: string;
  description: string;
  path: string;
  recent_status: string;
};

export type HomeDashboardSummary = {
  platform_name: string;
  platform_tagline: string;
  scenes: SceneEntryCardView[];
  recent_jobs: PlatformTaskListItemView[];
  recent_deliveries: DeliveryRecordView[];
  health: PlatformHealthSummary;
};

export type ApiEnvelope<T> = {
  code: number;
  message: string;
  data: T;
};
