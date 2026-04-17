import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  createDeliveryTarget,
  getFilteredDeliveryRecords,
  getDeliveryTargets,
  updateDeliveryTarget,
} from "./api";
import type {
  CreateDeliveryTargetInput,
  DeliveryRecordFilters,
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
