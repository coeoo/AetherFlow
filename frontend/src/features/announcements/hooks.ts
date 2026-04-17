import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  createAnnouncementDeliveries,
  getAnnouncementMonitorRunDetail,
  getAnnouncementMonitorRuns,
  createAnnouncementRun,
  getAnnouncementRunDetail,
  getAnnouncementSources,
  runAnnouncementSourceNow,
} from "./api";
import type { AnnouncementSource } from "./types";

export function useCreateAnnouncementRun() {
  return useMutation({
    mutationFn: createAnnouncementRun,
  });
}

export function useAnnouncementRunDetail(runId: string | null) {
  return useQuery({
    queryKey: ["announcements", "run", runId],
    queryFn: () => getAnnouncementRunDetail(runId!),
    enabled: Boolean(runId),
    refetchInterval: (query) => {
      const detail = query.state.data;
      if (!runId || !detail || detail.status !== "queued") {
        return false;
      }
      return 1500;
    },
  });
}

export function useAnnouncementMonitorRuns() {
  return useQuery({
    queryKey: ["announcements", "monitor-runs"],
    queryFn: getAnnouncementMonitorRuns,
  });
}

export function useAnnouncementMonitorRunDetail(fetchId: string | null) {
  return useQuery({
    queryKey: ["announcements", "monitor-runs", fetchId],
    queryFn: () => getAnnouncementMonitorRunDetail(fetchId!),
    enabled: Boolean(fetchId),
  });
}

export function useCreateAnnouncementRunDeliveries(runId: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (targetIds: string[]) => createAnnouncementDeliveries(runId, targetIds),
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({
          queryKey: ["announcements", "run", runId],
        }),
        queryClient.invalidateQueries({
          queryKey: ["deliveries", "records"],
        }),
      ]);
    },
  });
}

export function useAnnouncementSources() {
  return useQuery({
    queryKey: ["announcements", "sources"],
    queryFn: getAnnouncementSources,
  });
}

export function useRunAnnouncementSourceNow() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: runAnnouncementSourceNow,
    onSuccess: async () => {
      await queryClient.invalidateQueries({
        queryKey: ["announcements", "sources"],
      });
    },
  });
}

export function getSourceTypeLabel(sourceType: AnnouncementSource["source_type"]) {
  if (sourceType === "openwall") {
    return "Openwall";
  }
  if (sourceType === "nccsec") {
    return "NCC";
  }
  if (sourceType === "wechat") {
    return "微信";
  }
  return sourceType;
}
