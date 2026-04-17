import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  createDeliveryTarget,
  getFilteredDeliveryRecords,
  getDeliveryTargets,
  retryDeliveryRecord,
  scheduleDeliveryRecord,
  sendDeliveryRecord,
  testDeliveryTarget,
  updateDeliveryTarget,
} from "./api";
import type {
  CreateDeliveryTargetInput,
  DeliveryRecordFilters,
  ScheduleDeliveryRecordInput,
  UpdateDeliveryTargetInput,
} from "./types";

export function useDeliveryRecords(filters: DeliveryRecordFilters) {
  return useQuery({
    queryKey: ["deliveries", "records", filters],
    queryFn: () => getFilteredDeliveryRecords(filters),
  });
}

export function useDeliveryTargets() {
  return useQuery({
    queryKey: ["deliveries", "targets"],
    queryFn: getDeliveryTargets,
  });
}

export function useCreateDeliveryTarget() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (input: CreateDeliveryTargetInput) => createDeliveryTarget(input),
    onSuccess: async () => {
      await queryClient.invalidateQueries({
        queryKey: ["deliveries", "targets"],
      });
    },
  });
}

export function useUpdateDeliveryTarget() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (input: UpdateDeliveryTargetInput) => updateDeliveryTarget(input),
    onSuccess: async () => {
      await queryClient.invalidateQueries({
        queryKey: ["deliveries", "targets"],
      });
    },
  });
}

export function useTestDeliveryTarget() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (targetId: string) => testDeliveryTarget(targetId),
    onSuccess: async () => {
      await queryClient.invalidateQueries({
        queryKey: ["deliveries"],
      });
    },
  });
}

export function useSendDeliveryRecord() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (recordId: string) => sendDeliveryRecord(recordId),
    onSuccess: async () => {
      await queryClient.invalidateQueries({
        queryKey: ["deliveries"],
      });
    },
  });
}

export function useRetryDeliveryRecord() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (recordId: string) => retryDeliveryRecord(recordId),
    onSuccess: async () => {
      await queryClient.invalidateQueries({
        queryKey: ["deliveries"],
      });
    },
  });
}

export function useScheduleDeliveryRecord() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (input: ScheduleDeliveryRecordInput) => scheduleDeliveryRecord(input),
    onSuccess: async () => {
      await queryClient.invalidateQueries({
        queryKey: ["deliveries"],
      });
    },
  });
}
