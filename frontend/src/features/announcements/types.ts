export type AnnouncementRunSummary = {
  linux_related?: boolean | null;
  confidence?: number;
  notify_recommended?: boolean;
  primary_title?: string;
  error?: string;
};

export type AnnouncementDocument = {
  document_id: string;
  title: string;
  source_name: string;
  source_url: string | null;
  published_at: string | null;
  content_excerpt: string | null;
};

export type AnnouncementPackage = {
  package_id: string;
  confidence: number;
  severity: string | null;
  analyst_summary: string;
  notify_recommended: boolean;
  affected_products: unknown[];
  iocs: unknown[];
  remediation: unknown[];
  evidence: unknown[];
};

export type AnnouncementMatchedTarget = {
  target_id: string;
  name: string;
  channel_type: string;
  match_reason: string;
};

export type AnnouncementDeliveryRecord = {
  record_id: string;
  scene_name: string;
  source_ref_type: string | null;
  source_ref_id: string | null;
  target_id: string | null;
  target_name: string;
  channel_type: string | null;
  delivery_kind: string;
  status: string;
  error_message: string | null;
  scheduled_at: string | null;
  sent_at: string | null;
  created_at: string;
  payload_summary: Record<string, unknown>;
  response_snapshot: Record<string, unknown>;
};

export type AnnouncementDeliveryPanel = {
  run_id: string;
  notify_recommended: boolean;
  auto_send_applied: boolean;
  skip_reason: string | null;
  matched_targets: AnnouncementMatchedTarget[];
  recent_records: AnnouncementDeliveryRecord[];
};

export type AnnouncementRunListItem = {
  run_id: string;
  entry_mode: string;
  status: string;
  stage: string;
  input_snapshot: {
    input_mode?: string;
    source_url?: string;
  };
  summary: AnnouncementRunSummary;
  created_at: string;
};

export type AnnouncementRunDetail = {
  run_id: string;
  entry_mode: string;
  status: string;
  stage: string;
  summary: AnnouncementRunSummary;
  input_snapshot: Record<string, unknown>;
  document: AnnouncementDocument | null;
  package: AnnouncementPackage | null;
  delivery: AnnouncementDeliveryPanel | null;
};

export type AnnouncementSource = {
  source_id: string;
  name: string;
  source_type: string;
  enabled: boolean;
  schedule_cron: string;
  config: Record<string, unknown>;
  delivery_policy: Record<string, unknown>;
};

export type AnnouncementRunNowResult = {
  job_id: string;
  source_id: string;
  job_type: string;
  status: string;
};

export type AnnouncementCreateDeliveriesResult = {
  run_id: string;
  created_count: number;
  records: Array<{
    record_id: string;
    target_id: string;
    target_name: string;
    delivery_kind: string;
    status: string;
    scheduled_at: string | null;
  }>;
};

export type ApiEnvelope<T> = {
  code: number;
  message: string;
  data: T;
};
