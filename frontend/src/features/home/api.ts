import type { ApiEnvelope, HomeDashboardSummary } from "./types";

function getApiBaseUrl() {
  const env = (import.meta as unknown as { env?: Record<string, string | undefined> }).env ?? {};
  return env.VITE_API_BASE_URL?.replace(/\/$/, "") ?? "";
}

export async function getHomeSummary(): Promise<HomeDashboardSummary> {
  const response = await fetch(`${getApiBaseUrl()}/api/v1/platform/home-summary`);
  if (!response.ok) {
    throw new Error(`请求失败: ${response.status}`);
  }

  const payload = (await response.json()) as ApiEnvelope<HomeDashboardSummary>;
  return payload.data;
}
