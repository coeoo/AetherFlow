import type {
  ApiEnvelope,
  CreateDeliveryTargetInput,
  DeliveryRecordFilters,
  DeliveryRecordView,
  DeliveryTargetView,
  ScheduleDeliveryRecordInput,
  UpdateDeliveryTargetInput,
} from "./types";

function getApiBaseUrl() {
  const env = (import.meta as unknown as { env?: Record<string, string | undefined> }).env ?? {};
  return env.VITE_API_BASE_URL?.replace(/\/$/, "") ?? "";
}

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${getApiBaseUrl()}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
    ...init,
  });

  if (!response.ok) {
    throw new Error(`请求失败: ${response.status}`);
  }

  const payload = (await response.json()) as ApiEnvelope<T>;
  return payload.data;
}

export function getFilteredDeliveryRecords(filters: DeliveryRecordFilters) {
  const query = new URLSearchParams();
  if (filters.scene_name) {
    query.set("scene_name", filters.scene_name);
  }
  if (filters.status) {
    query.set("status", filters.status);
  }
  if (filters.channel_type) {
    query.set("channel_type", filters.channel_type);
  }
  if (filters.delivery_kind) {
    query.set("delivery_kind", filters.delivery_kind);
  }
  return requestJson<DeliveryRecordView[]>(`/api/v1/platform/delivery-records?${query.toString()}`);
}

export function getDeliveryTargets() {
  return requestJson<DeliveryTargetView[]>("/api/v1/platform/delivery-targets");
}

export function createDeliveryTarget(input: CreateDeliveryTargetInput) {
  return requestJson<DeliveryTargetView>("/api/v1/platform/delivery-targets", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function updateDeliveryTarget(input: UpdateDeliveryTargetInput) {
  const { target_id, ...payload } = input;
  return requestJson<DeliveryTargetView>(`/api/v1/platform/delivery-targets/${input.target_id}`, {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
}

export function testDeliveryTarget(targetId: string) {
  return requestJson<DeliveryRecordView>(`/api/v1/platform/delivery-targets/${targetId}/test`, {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export function sendDeliveryRecord(recordId: string) {
  return requestJson<DeliveryRecordView>(`/api/v1/platform/delivery-records/${recordId}/send`, {
    method: "POST",
  });
}

export function retryDeliveryRecord(recordId: string) {
  return requestJson<DeliveryRecordView>(`/api/v1/platform/delivery-records/${recordId}/retry`, {
    method: "POST",
  });
}

export function scheduleDeliveryRecord(input: ScheduleDeliveryRecordInput) {
  return requestJson<DeliveryRecordView>(`/api/v1/platform/delivery-records/${input.record_id}/schedule`, {
    method: "POST",
    body: JSON.stringify({
      scheduled_at: input.scheduled_at,
    }),
  });
}
