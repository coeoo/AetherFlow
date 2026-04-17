export type PlatformTaskListItemView = {
  job_id: string;
  scene_name: string;
  job_type: string;
  trigger_kind: string;
  status: string;
  scene_run_id: string | null;
  payload_summary: Record<string, unknown>;
  last_error: string | null;
  last_attempt_at: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
};

export type PlatformTaskAttemptView = {
  attempt_id: string;
  attempt_no: number;
  status: string;
  worker_name: string | null;
  error_message: string | null;
  started_at: string;
  finished_at: string | null;
};

export type PlatformTaskDetailView = {
  job_id: string;
  scene_name: string;
  job_type: string;
  trigger_kind: string;
  status: string;
  scene_run_id: string | null;
  payload_summary: Record<string, unknown>;
  last_error: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  attempts: PlatformTaskAttemptView[];
};

export type PlatformTaskFilters = {
  scene_name: string | null;
  status: string | null;
  trigger_kind: string | null;
  page: number;
  page_size: number;
};

export type PlatformTaskListResponse = {
  items: PlatformTaskListItemView[];
  total: number;
  page: number;
  page_size: number;
};

export type PlatformTaskRetryResult = {
  job_id: string;
  status: string;
  scene_name: string;
  job_type: string;
  trigger_kind: string;
  queued_at: string;
};

export type ApiEnvelope<T> = {
  code: number;
  message: string;
  data: T;
};
