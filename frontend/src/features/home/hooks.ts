import { useQuery } from "@tanstack/react-query";

import { getHomeSummary } from "./api";

export function useHomeSummary() {
  return useQuery({
    queryKey: ["home", "summary"],
    queryFn: getHomeSummary,
    refetchInterval: 60_000,
  });
}
