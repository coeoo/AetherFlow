import { useMutation, useQuery } from "@tanstack/react-query";

import { createCveRun, getCveRunDetail, getCveRunHistory, getPatchContent } from "./api";

export function useCreateCveRun() {
  return useMutation({
    mutationFn: createCveRun,
  });
}

export function useCveRunHistory() {
  return useQuery({
    queryKey: ["cve", "runs"],
    queryFn: getCveRunHistory,
  });
}

export function useCveRunDetail(runId: string | null) {
  return useQuery({
    queryKey: ["cve", "run", runId],
    queryFn: () => getCveRunDetail(runId!),
    enabled: Boolean(runId),
    refetchInterval: (query) => {
      const detail = query.state.data;
      if (!runId || !detail || detail.progress.terminal) {
        return false;
      }
      return 1500;
    },
  });
}

export function usePatchContent(runId: string | null, patchId: string | null) {
  return useQuery({
    queryKey: ["cve", "patch-content", runId, patchId],
    queryFn: () => getPatchContent(runId!, patchId!),
    enabled: Boolean(runId && patchId),
  });
}
