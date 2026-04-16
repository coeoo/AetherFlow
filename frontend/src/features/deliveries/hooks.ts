import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { getFilteredDeliveryRecords, getDeliveryTargets, updateDeliveryTarget } from "./api";
import type { UpdateDeliveryTargetInput } from "./types";

export function useDeliveryRecords(sceneName: string, status: string | null = null) {
  return useQuery({
    queryKey: ["deliveries", "records", sceneName, status],
    queryFn: () => getFilteredDeliveryRecords(sceneName, status),
  });
}

export function useDeliveryTargets() {
  return useQuery({
    queryKey: ["deliveries", "targets"],
    queryFn: getDeliveryTargets,
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
