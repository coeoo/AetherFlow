import type { ApiEnvelope, CVEPatchContent, CVERunDetail } from "./types";

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

export function createCveRun(cveId: string) {
  return requestJson<CVERunDetail>("/api/v1/cve/runs", {
    method: "POST",
    body: JSON.stringify({ cve_id: cveId }),
  });
}

export function getCveRunDetail(runId: string) {
  return requestJson<CVERunDetail>(`/api/v1/cve/runs/${runId}`);
}

export function getPatchContent(runId: string, candidateUrl: string) {
  const params = new URLSearchParams({ candidate_url: candidateUrl });
  return requestJson<CVEPatchContent>(`/api/v1/cve/runs/${runId}/patch-content?${params.toString()}`);
}
