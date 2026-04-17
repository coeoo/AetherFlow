import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { getPlatformTaskDetail, getPlatformTasks, retryPlatformTask } from "./api";
import type { PlatformTaskFilters } from "./types";

export function usePlatformTasks(filters: PlatformTaskFilters) {
  return useQuery({
    queryKey: ["platform", "tasks", filters],
    queryFn: () => getPlatformTasks(filters),
  });
}

export function usePlatformTaskDetail(jobId: string | null) {
  return useQuery({
    queryKey: ["platform", "tasks", "detail", jobId],
    queryFn: () => getPlatformTaskDetail(jobId!),
    enabled: Boolean(jobId),
  });
}

export function useRetryPlatformTask() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: retryPlatformTask,
    onSuccess: async (_, jobId) => {
      await queryClient.invalidateQueries({
        queryKey: ["platform", "tasks"],
      });
      await queryClient.invalidateQueries({
        queryKey: ["platform", "tasks", "detail", jobId],
      });
      await queryClient.invalidateQueries({
        queryKey: ["home", "summary"],
      });
    },
  });
}
