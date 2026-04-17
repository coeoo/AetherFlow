import { render, screen } from "@testing-library/react";
import { readFileSync } from "node:fs";
import { createMemoryRouter, RouterProvider } from "react-router-dom";

import { AppProviders } from "../app/providers";
import { routes } from "../app/router";

function renderPath(path: string) {
  const router = createMemoryRouter(routes, {
    initialEntries: [path],
    future: {
      v7_startTransition: true,
    },
  });

  render(
    <AppProviders>
      <RouterProvider
        router={router}
        future={{
          v7_startTransition: true,
        }}
      />
    </AppProviders>,
  );
}

function mockJsonResponse(data: unknown) {
  return {
    ok: true,
    json: async () => data,
  } as Response;
}

beforeEach(() => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/v1/platform/home-summary")) {
        return mockJsonResponse({
          code: 0,
          message: "success",
          data: {
            platform_name: "AetherFlow",
            platform_tagline: "把原始安全信号处理成可复查的结构化情报",
            scenes: [
              {
                scene_name: "cve",
                title: "CVE 补丁检索",
                description: "输入一个 CVE 编号，快速得到补丁线索、证据和 Diff。",
                path: "/cve",
                recent_status: "CVE-2024-3094 · running",
              },
              {
                scene_name: "announcement",
                title: "安全公告提取",
                description: "输入公告 URL 或进入监控视图，生成结构化情报包与投递建议。",
                path: "/announcements",
                recent_status: "手动提取 · failed",
              },
            ],
            recent_jobs: [],
            recent_deliveries: [],
            health: {
              api: "healthy",
              database: "healthy",
              worker: "degraded",
              scheduler: "down",
              notes: ["worker 当前状态为 degraded", "scheduler 当前状态为 down"],
            },
          },
        });
      }

      if (url.endsWith("/api/v1/platform/health/summary")) {
        return mockJsonResponse({
          api: "healthy",
          database: "healthy",
          worker: "degraded",
          scheduler: "down",
          notes: ["worker 当前状态为 degraded", "scheduler 当前状态为 down"],
        });
      }

      if (url.includes("/api/v1/platform/tasks?")) {
        return mockJsonResponse({
          code: 0,
          message: "success",
          data: {
            items: [],
            total: 0,
            page: 1,
            page_size: 20,
          },
        });
      }

      if (url.endsWith("/api/v1/announcements/sources")) {
        return mockJsonResponse({
          code: 0,
          message: "success",
          data: [],
        });
      }

      if (url.endsWith("/api/v1/announcements/runs/run-002")) {
        return mockJsonResponse({
          code: 0,
          message: "success",
          data: {
            run_id: "run-002",
            entry_mode: "monitor_source",
            status: "succeeded",
            stage: "finalize_run",
            summary: {
              linux_related: true,
              confidence: 0.9,
              notify_recommended: true,
              primary_title: "OpenSSL advisory",
            },
            input_snapshot: {
              source_url: "https://www.openwall.com/lists/oss-security/2026/04/15/42",
            },
            document: {
              document_id: "document-002",
              title: "OpenSSL advisory",
              source_name: "Openwall",
              source_url: "https://www.openwall.com/lists/oss-security/2026/04/15/42",
              published_at: "2026-04-15T09:00:00+00:00",
              content_excerpt: "OpenSSL vulnerability for Linux systems",
            },
            package: {
              package_id: "package-002",
              confidence: 0.9,
              severity: "high",
              analyst_summary: "检测到与 Linux 生态相关的安全公告。",
              notify_recommended: true,
              affected_products: [],
              iocs: [],
              remediation: [],
              evidence: [],
            },
            delivery: {
              run_id: "run-002",
              notify_recommended: true,
              auto_send_applied: false,
              skip_reason: null,
              matched_targets: [
                {
                  target_id: "target-001",
                  name: "安全响应群",
                  channel_type: "wecom",
                  match_reason: "命中来源投递白名单",
                },
              ],
              recent_records: [],
            },
          },
        });
      }

      if (url.includes("/api/v1/platform/delivery-records")) {
        return mockJsonResponse({
          code: 0,
          message: "success",
          data: [],
        });
      }

      if (url.includes("/api/v1/platform/delivery-targets")) {
        return mockJsonResponse({
          code: 0,
          message: "success",
          data: [],
        });
      }

      throw new Error(`未预期的请求: ${url}`);
    }),
  );
});

afterEach(() => {
  vi.restoreAllMocks();
});

test.each([
  ["/", "平台首页"],
  ["/cve", "CVE 检索工作台"],
  ["/cve/runs/run-001", "CVE 运行详情"],
  ["/announcements", "安全公告工作台"],
  ["/announcements?tab=monitoring", "安全公告工作台"],
  ["/announcements/sources", "监控源管理"],
  ["/announcements/runs/run-002", "安全公告情报包详情"],
  ["/deliveries", "投递中心"],
  ["/deliveries?tab=records", "投递中心"],
  ["/system/tasks", "平台任务中心"],
  ["/system/health", "系统状态"],
])("renders route shell for %s", async (path, heading) => {
  renderPath(path);

  expect(await screen.findByRole("heading", { name: heading })).toBeInTheDocument();
});

test("keeps utility navigation aligned to 投递中心 and 系统 only", async () => {
  renderPath("/");

  expect(await screen.findByRole("link", { name: "投递中心" })).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "系统" })).toBeInTheDocument();
  expect(screen.queryByRole("link", { name: "任务中心" })).not.toBeInTheDocument();
  expect(screen.queryByRole("link", { name: "系统状态" })).not.toBeInTheDocument();
});

test("renders the monitoring workbench content for /announcements?tab=monitoring", async () => {
  renderPath("/announcements?tab=monitoring");

  expect(await screen.findByText("监控批次视图已接入")).toBeInTheDocument();
  expect(
    screen.getAllByText("当前工作台正在复用监控批次占位模块，后续可平滑拆分为独立监控页。"),
  ).toHaveLength(2);
  expect(screen.getByText("当前监控源")).toBeInTheDocument();
});

test("exposes a real #delivery anchor in announcement run detail", async () => {
  renderPath("/announcements/runs/run-002");

  expect(await screen.findByRole("heading", { name: "安全公告情报包详情" })).toBeInTheDocument();
  expect(await screen.findByText("投递建议与记录")).toBeInTheDocument();
  expect(document.getElementById("delivery")).not.toBeNull();
  expect(screen.getByRole("link", { name: "跳到投递区块" })).toHaveAttribute(
    "href",
    "/announcements/runs/run-002#delivery",
  );
  expect(screen.getByRole("link", { name: "进入投递中心" })).toHaveAttribute(
    "href",
    "/deliveries?tab=records",
  );
});

test("loads the Manrope font from the application entry", () => {
  const mainEntry = readFileSync(`${process.cwd()}/src/main.tsx`, "utf-8");

  expect(mainEntry).toContain("@fontsource/manrope");
});

test("renders aggregated platform summary sections on the home page", async () => {
  renderPath("/");

  expect(await screen.findByText("平台健康摘要")).toBeInTheDocument();
  expect(screen.getAllByText("最近任务").length).toBeGreaterThan(0);
  expect(screen.getAllByText("最近投递").length).toBeGreaterThan(0);
  expect(screen.getByText("API")).toBeInTheDocument();
  expect(screen.getAllByText("healthy").length).toBeGreaterThan(0);
  expect(screen.getByRole("link", { name: "查看系统状态" })).toHaveAttribute("href", "/system/health");
  expect(screen.getByRole("link", { name: "进入任务中心" })).toHaveAttribute("href", "/system/tasks");
});

test("renders platform health summary details on the system page", async () => {
  renderPath("/system/health");

  expect(await screen.findByText("健康摘要已接入")).toBeInTheDocument();
  expect(screen.getByText("Database")).toBeInTheDocument();
  expect(screen.getByText("Worker")).toBeInTheDocument();
  expect(screen.getByText("Scheduler")).toBeInTheDocument();
  expect(screen.getByText("worker 当前状态为 degraded")).toBeInTheDocument();
  expect(screen.getByText("scheduler 当前状态为 down")).toBeInTheDocument();
});
