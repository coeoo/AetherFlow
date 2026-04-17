import type { PlatformHealthSummary } from "./types";

function getApiBaseUrl() {
  const env = (import.meta as unknown as { env?: Record<string, string | undefined> }).env ?? {};
  return env.VITE_API_BASE_URL?.replace(/\/$/, "") ?? "";
}

export async function getPlatformHealthSummary(): Promise<PlatformHealthSummary> {
  const response = await fetch(`${getApiBaseUrl()}/api/v1/platform/health/summary`);
  if (!response.ok) {
    throw new Error(`请求失败: ${response.status}`);
  }

  return (await response.json()) as PlatformHealthSummary;
}
