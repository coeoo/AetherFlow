import type { PlatformHealthStatus, PlatformHealthSummary } from "./types";

type HealthSummaryItem = {
  key: keyof Omit<PlatformHealthSummary, "notes">;
  label: string;
  value: PlatformHealthStatus;
};

const healthStatusPriority: Record<PlatformHealthStatus, number> = {
  healthy: 0,
  degraded: 1,
  down: 2,
};

export function getPlatformHealthItems(summary: PlatformHealthSummary): HealthSummaryItem[] {
  return [
    { key: "api", label: "API", value: summary.api },
    { key: "database", label: "Database", value: summary.database },
    { key: "worker", label: "Worker", value: summary.worker },
    { key: "scheduler", label: "Scheduler", value: summary.scheduler },
  ];
}

export function getPlatformHealthLevel(summary: PlatformHealthSummary): PlatformHealthStatus {
  const items = getPlatformHealthItems(summary);

  return items.reduce<PlatformHealthStatus>((currentLevel, item) => {
    if (healthStatusPriority[item.value] > healthStatusPriority[currentLevel]) {
      return item.value;
    }
    return currentLevel;
  }, "healthy");
}
