import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef } from "react";

import { createCveRun, getCveRunDetail, getCveRunHistory, getPatchContent } from "./api";
import type { CVERunListItem } from "./types";

export function useCreateCveRun() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: createCveRun,
    onSuccess: async (createdRun) => {
      queryClient.setQueryData<CVERunListItem[]>(["cve", "runs"], (currentRuns) => {
        const deduplicatedRuns = (currentRuns ?? []).filter((run) => run.run_id !== createdRun.run_id);
        return [createdRun, ...deduplicatedRuns];
      });

      await queryClient.invalidateQueries({
        queryKey: ["cve", "runs"],
      });
    },
  });
}

export function useCveRunHistory(limit = 20) {
  return useQuery({
    queryKey: ["cve", "runs"],
    queryFn: () => getCveRunHistory(limit),
  });
}

type UseCveRunDetailOptions = {
  refreshHistoryOnTerminal?: boolean;
};

export function useCveRunDetail(runId: string | null, options?: UseCveRunDetailOptions) {
  const queryClient = useQueryClient();
  const hasRefreshedTerminalHistoryRef = useRef(false);
  const detailQuery = useQuery({
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

  useEffect(() => {
    const shouldRefreshHistory = options?.refreshHistoryOnTerminal ?? false;
    const detail = detailQuery.data;
    if (!shouldRefreshHistory || !runId || !detail?.progress.terminal) {
      hasRefreshedTerminalHistoryRef.current = false;
      return;
    }
    if (hasRefreshedTerminalHistoryRef.current) {
      return;
    }
    hasRefreshedTerminalHistoryRef.current = true;
    void queryClient.invalidateQueries({
      queryKey: ["cve", "runs"],
    });
  }, [detailQuery.data, options?.refreshHistoryOnTerminal, queryClient, runId]);

  return detailQuery;
}

export function usePatchContent(runId: string | null, patchId: string | null) {
  return useQuery({
    queryKey: ["cve", "patch-content", runId, patchId],
    queryFn: () => getPatchContent(runId!, patchId!),
    enabled: Boolean(runId && patchId),
  });
}
