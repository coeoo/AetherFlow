export type PlatformHealthStatus = "healthy" | "degraded" | "down";

export type PlatformHealthSummary = {
  api: PlatformHealthStatus;
  database: PlatformHealthStatus;
  worker: PlatformHealthStatus;
  scheduler: PlatformHealthStatus;
  notes: string[];
};
