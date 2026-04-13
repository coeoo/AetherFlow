import { useMutation, useQuery } from "@tanstack/react-query";

import { createCveRun, getCveRunDetail, getPatchContent } from "./api";

export function useCreateCveRun() {
  return useMutation({
    mutationFn: createCveRun,
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

export function usePatchContent(runId: string | null, candidateUrl: string | null) {
  return useQuery({
    queryKey: ["cve", "patch-content", runId, candidateUrl],
    queryFn: () => getPatchContent(runId!, candidateUrl!),
    enabled: Boolean(runId && candidateUrl),
  });
}
