import type {
  ApiEnvelope,
  DeliveryRecordView,
  DeliveryTargetView,
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

export function getDeliveryRecords(sceneName: string) {
  return requestJson<DeliveryRecordView[]>(
    `/api/v1/platform/delivery-records?scene_name=${encodeURIComponent(sceneName)}`,
  );
}

export function getFilteredDeliveryRecords(sceneName: string, status: string | null) {
  const query = new URLSearchParams({ scene_name: sceneName });
  if (status) {
    query.set("status", status);
  }
  return requestJson<DeliveryRecordView[]>(`/api/v1/platform/delivery-records?${query.toString()}`);
}

export function getDeliveryTargets() {
  return requestJson<DeliveryTargetView[]>("/api/v1/platform/delivery-targets");
}

export function updateDeliveryTarget(input: UpdateDeliveryTargetInput) {
  return requestJson<DeliveryTargetView>(`/api/v1/platform/delivery-targets/${input.target_id}`, {
    method: "PATCH",
    body: JSON.stringify({ enabled: input.enabled }),
  });
}
