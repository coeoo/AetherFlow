export type DeliveryRecordView = {
  record_id: string;
  scene_name: string;
  source_ref_type: string | null;
  source_ref_id: string | null;
  target_id: string | null;
  target_name: string;
  channel_type: string | null;
  status: string;
  error_message: string | null;
  created_at: string;
  payload_summary: Record<string, unknown>;
};

export type DeliveryTargetView = {
  target_id: string;
  name: string;
  channel_type: string;
  enabled: boolean;
  config_summary: Record<string, unknown>;
};

export type UpdateDeliveryTargetInput = {
  target_id: string;
  enabled: boolean;
};

export type ApiEnvelope<T> = {
  code: number;
  message: string;
  data: T;
};
