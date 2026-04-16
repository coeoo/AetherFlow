import type {
  AnnouncementCreateDeliveriesResult,
  AnnouncementRunDetail,
  AnnouncementRunListItem,
  AnnouncementRunNowResult,
  AnnouncementSource,
  ApiEnvelope,
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

export function createAnnouncementRun(sourceUrl: string) {
  return requestJson<AnnouncementRunListItem>("/api/v1/announcements/runs", {
    method: "POST",
    body: JSON.stringify({
      input_mode: "url",
      source_url: sourceUrl,
    }),
  });
}

export function getAnnouncementRunDetail(runId: string) {
  return requestJson<AnnouncementRunDetail>(`/api/v1/announcements/runs/${runId}`);
}

export function createAnnouncementDeliveries(runId: string) {
  return requestJson<AnnouncementCreateDeliveriesResult>(
    `/api/v1/announcements/runs/${runId}/deliveries`,
    {
      method: "POST",
      body: JSON.stringify({}),
    },
  );
}

export function getAnnouncementSources() {
  return requestJson<AnnouncementSource[]>("/api/v1/announcements/sources");
}

export function runAnnouncementSourceNow(sourceId: string) {
  return requestJson<AnnouncementRunNowResult>(`/api/v1/announcements/sources/${sourceId}/run-now`, {
    method: "POST",
  });
}
