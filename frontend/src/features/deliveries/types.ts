export type DeliveryRecordView = {
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

export type DeliveryRecordFilters = {
  scene_name: string | null;
  status: string | null;
  channel_type: string | null;
  delivery_kind: string | null;
};

export type DeliveryTargetView = {
  target_id: string;
  name: string;
  channel_type: string;
  enabled: boolean;
  config_json: Record<string, unknown>;
  config_summary: Record<string, unknown>;
};

export type CreateDeliveryTargetInput = {
  name: string;
  channel_type: string;
  enabled: boolean;
  config_json: Record<string, unknown>;
};

export type UpdateDeliveryTargetInput = Partial<CreateDeliveryTargetInput> & {
  target_id: string;
};

export type ScheduleDeliveryRecordInput = {
  record_id: string;
  scheduled_at: string;
};

export type ApiEnvelope<T> = {
  code: number;
  message: string;
  data: T;
};
