import { useQuery } from "@tanstack/react-query";

import { getPlatformHealthSummary } from "./api";

export function usePlatformHealthSummary() {
  return useQuery({
    queryKey: ["system", "health-summary"],
    queryFn: getPlatformHealthSummary,
    refetchInterval: 60_000,
  });
}
