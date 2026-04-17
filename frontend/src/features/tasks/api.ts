import type {
  ApiEnvelope,
  PlatformTaskDetailView,
  PlatformTaskFilters,
  PlatformTaskListResponse,
  PlatformTaskRetryResult,
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

export function getPlatformTasks(filters: PlatformTaskFilters) {
  const params = new URLSearchParams();
  if (filters.scene_name) {
    params.set("scene_name", filters.scene_name);
  }
  if (filters.status) {
    params.set("status", filters.status);
  }
  if (filters.trigger_kind) {
    params.set("trigger_kind", filters.trigger_kind);
  }
  params.set("page", String(filters.page));
  params.set("page_size", String(filters.page_size));

  return requestJson<PlatformTaskListResponse>(`/api/v1/platform/tasks?${params.toString()}`);
}

export function getPlatformTaskDetail(jobId: string) {
  return requestJson<PlatformTaskDetailView>(`/api/v1/platform/tasks/${jobId}`);
}

export function retryPlatformTask(jobId: string) {
  return requestJson<PlatformTaskRetryResult>(`/api/v1/platform/tasks/${jobId}/retry`, {
    method: "POST",
  });
}
