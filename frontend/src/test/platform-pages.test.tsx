import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router-dom";

import { AppProviders } from "../app/providers";
import { queryClient } from "../app/query-client";
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

afterEach(() => {
  queryClient.clear();
  vi.restoreAllMocks();
});

test("home page renders aggregated summary from home-summary api", async () => {
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
                path: "/patch",
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
            recent_jobs: [
              {
                job_id: "job-001",
                scene_name: "cve",
                job_type: "cve_patch_fast_first",
                trigger_kind: "manual",
                status: "running",
                scene_run_id: "run-001",
                payload_summary: {
                  cve_id: "CVE-2024-3094",
                },
                last_error: null,
                last_attempt_at: "2026-04-17T10:00:00+00:00",
                created_at: "2026-04-17T10:00:00+00:00",
                started_at: "2026-04-17T10:00:00+00:00",
                finished_at: null,
              },
            ],
            recent_deliveries: [
              {
                record_id: "record-001",
                scene_name: "announcement",
                source_ref_type: "announcement_run",
                source_ref_id: "run-002",
                target_id: "target-001",
                target_name: "安全响应群",
                channel_type: "wecom",
                status: "prepared",
                error_message: null,
                created_at: "2026-04-17T10:02:00+00:00",
                payload_summary: {
                  title: "OpenSSL advisory",
                },
              },
            ],
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

      throw new Error(`未预期的请求: ${url}`);
    }),
  );

  renderPath("/");

  expect((await screen.findAllByText("最近任务")).length).toBeGreaterThan(0);
  expect(await screen.findByText("CVE-2024-3094")).toBeInTheDocument();
  expect(screen.getByText("OpenSSL advisory")).toBeInTheDocument();
  expect(screen.getByText("worker 当前状态为 degraded")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "进入任务中心" })).toHaveAttribute("href", "/system/tasks");
});

test("task center renders list, detail and retry flow from platform tasks api", async () => {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);

    if (url.includes("/api/v1/platform/tasks?") && !init?.method) {
      return mockJsonResponse({
        code: 0,
        message: "success",
        data: {
          items: [
            {
              job_id: "job-001",
              scene_name: "announcement",
              job_type: "announcement_manual_extract",
              trigger_kind: "manual",
              status: "failed",
              scene_run_id: "run-001",
              payload_summary: {
                input_mode: "url",
                source_url: "https://example.com/advisory",
              },
              last_error: "extract failed",
              last_attempt_at: "2026-04-17T10:10:00+00:00",
              created_at: "2026-04-17T10:00:00+00:00",
              started_at: "2026-04-17T10:01:00+00:00",
              finished_at: "2026-04-17T10:10:00+00:00",
            },
          ],
          total: 1,
          page: 1,
          page_size: 20,
        },
      });
    }

    if (url.endsWith("/api/v1/platform/tasks/job-001") && !init?.method) {
      return mockJsonResponse({
        code: 0,
        message: "success",
        data: {
          job_id: "job-001",
          scene_name: "announcement",
          job_type: "announcement_manual_extract",
          trigger_kind: "manual",
          status: "failed",
          scene_run_id: "run-001",
          payload_summary: {
            input_mode: "url",
            source_url: "https://example.com/advisory",
          },
          last_error: "extract failed",
          created_at: "2026-04-17T10:00:00+00:00",
          started_at: "2026-04-17T10:01:00+00:00",
          finished_at: "2026-04-17T10:10:00+00:00",
          attempts: [
            {
              attempt_id: "attempt-002",
              attempt_no: 2,
              status: "failed",
              worker_name: "worker-b",
              error_message: "extract failed",
              started_at: "2026-04-17T10:05:00+00:00",
              finished_at: "2026-04-17T10:10:00+00:00",
            },
            {
              attempt_id: "attempt-001",
              attempt_no: 1,
              status: "failed",
              worker_name: "worker-a",
              error_message: "network timeout",
              started_at: "2026-04-17T10:01:00+00:00",
              finished_at: "2026-04-17T10:02:00+00:00",
            },
          ],
        },
      });
    }

    if (url.endsWith("/api/v1/platform/tasks/job-001/retry") && init?.method === "POST") {
      return mockJsonResponse({
        code: 0,
        message: "success",
        data: {
          job_id: "job-001",
          status: "queued",
          scene_name: "announcement",
          job_type: "announcement_manual_extract",
          trigger_kind: "manual",
          queued_at: "2026-04-17T10:12:00+00:00",
        },
      });
    }

    throw new Error(`未预期的请求: ${url}`);
  });

  vi.stubGlobal("fetch", fetchMock);

  renderPath("/system/tasks");

  expect(await screen.findByText("job-001")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "查看详情" }));

  expect(await screen.findByText((content) => content.includes("run-001"))).toBeInTheDocument();
  expect(screen.getByText("extract failed")).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "重新排队" }));

  expect(await screen.findByText("任务已重新排队")).toBeInTheDocument();
  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining("/api/v1/platform/tasks/job-001/retry"),
      expect.objectContaining({ method: "POST" }),
    );
  });
});
