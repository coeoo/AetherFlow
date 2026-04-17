import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router-dom";

import { queryClient } from "../app/query-client";
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

  return router;
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

test("announcement workbench submits url mode and shows latest run preview", async () => {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);

    if (url.endsWith("/api/v1/announcements/runs") && init?.method === "POST") {
      return mockJsonResponse({
        code: 0,
        message: "success",
        data: {
          run_id: "announcement-run-001",
          entry_mode: "manual_url",
          status: "queued",
          stage: "fetch_source",
          input_snapshot: {
            input_mode: "url",
            source_url: "https://example.com/advisory",
          },
          summary: {},
          created_at: "2026-04-15T10:00:00+00:00",
        },
      });
    }

    if (url.endsWith("/api/v1/announcements/runs/announcement-run-001")) {
      return mockJsonResponse({
        code: 0,
        message: "success",
        data: {
          run_id: "announcement-run-001",
          entry_mode: "manual_url",
          status: "succeeded",
          stage: "finalize_run",
          summary: {
            linux_related: true,
            confidence: 0.9,
            notify_recommended: true,
            primary_title: "OpenSSL advisory",
          },
          input_snapshot: {
            input_mode: "url",
            source_url: "https://example.com/advisory",
          },
          document: {
            document_id: "document-001",
            title: "OpenSSL advisory",
            source_name: "Manual URL",
            source_url: "https://example.com/advisory",
            published_at: null,
            content_excerpt: "OpenSSL vulnerability for Linux systems",
          },
          package: {
            package_id: "package-001",
            confidence: 0.9,
            severity: "high",
            analyst_summary: "检测到与 Linux 生态相关的安全公告。",
            notify_recommended: true,
            affected_products: [],
            iocs: [],
            remediation: [],
            evidence: [],
          },
        },
      });
    }

    throw new Error(`未预期的请求: ${url}`);
  });

  vi.stubGlobal("fetch", fetchMock);

  renderPath("/announcements");

  fireEvent.change(screen.getByLabelText("公告 URL"), {
    target: { value: "https://example.com/advisory" },
  });
  fireEvent.click(screen.getByRole("button", { name: "开始提取" }));

  expect(await screen.findByText("OpenSSL advisory")).toBeInTheDocument();
  expect(screen.getByText("检测到与 Linux 生态相关的安全公告。")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "查看详情" })).toHaveAttribute(
    "href",
    "/announcements/runs/announcement-run-001",
  );
});

test("announcement sources page loads source list and exposes run-now action", async () => {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);

    if (url.endsWith("/api/v1/announcements/sources") && !init?.method) {
      return mockJsonResponse({
        code: 0,
        message: "success",
        data: [
          {
            source_id: "source-001",
            name: "Openwall OSS Security",
            source_type: "openwall",
            enabled: true,
            schedule_cron: "0 */2 * * *",
            config: { days_back: 3, max_documents: 5 },
            delivery_policy: {},
          },
        ],
      });
    }

    if (url.endsWith("/api/v1/announcements/sources/source-001/run-now")) {
      return mockJsonResponse({
        code: 0,
        message: "success",
        data: {
          job_id: "job-001",
          source_id: "source-001",
          job_type: "announcement_monitor_fetch",
          status: "queued",
        },
      });
    }

    throw new Error(`未预期的请求: ${url}`);
  });

  vi.stubGlobal("fetch", fetchMock);

  renderPath("/announcements/sources");

  expect(await screen.findByText("Openwall OSS Security")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "立即试跑" }));

  expect(await screen.findByText("试跑任务已创建")).toBeInTheDocument();
  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });
  expect(fetchMock).toHaveBeenCalledWith(
    expect.stringContaining("/api/v1/announcements/sources/source-001/run-now"),
    expect.objectContaining({ method: "POST" }),
  );
});

test("announcement detail page renders package summary from api payload", async () => {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/api/v1/announcements/runs/run-001")) {
      return mockJsonResponse({
        code: 0,
        message: "success",
        data: {
          run_id: "run-001",
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
            document_id: "document-001",
            title: "OpenSSL advisory",
            source_name: "Openwall",
            source_url: "https://www.openwall.com/lists/oss-security/2026/04/15/42",
            published_at: "2026-04-15T09:00:00+00:00",
            content_excerpt: "OpenSSL vulnerability for Linux systems",
          },
          package: {
            package_id: "package-001",
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
            run_id: "run-001",
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
              {
                target_id: "target-002",
                name: "邮件通知组",
                channel_type: "email",
                match_reason: "命中平台启用目标",
              },
            ],
            recent_records: [],
          },
        },
      });
    }

    if (url.endsWith("/api/v1/announcements/runs/run-001/deliveries") && init?.method === "POST") {
      return mockJsonResponse({
        code: 0,
        message: "success",
        data: {
          run_id: "run-001",
          created_count: 1,
          records: [
            {
              target_id: "target-002",
              target_name: "邮件通知组",
              status: "prepared",
            },
          ],
        },
      });
    }

    throw new Error(`未预期的请求: ${url}`);
  });

  vi.stubGlobal("fetch", fetchMock);

  renderPath("/announcements/runs/run-001");

  expect(await screen.findByText("OpenSSL advisory")).toBeInTheDocument();
  expect(screen.getByText("Openwall")).toBeInTheDocument();
  expect(screen.getByText(/置信度：0\.90/)).toBeInTheDocument();
  expect(screen.getByText(/投递建议：建议投递/)).toBeInTheDocument();
  expect(screen.getByText("检测到与 Linux 生态相关的安全公告。")).toBeInTheDocument();
  expect(screen.getByText("安全响应群")).toBeInTheDocument();
  expect(screen.getByText(/wecom · 命中来源投递白名单/)).toBeInTheDocument();
  expect(screen.getByText("邮件通知组")).toBeInTheDocument();

  fireEvent.click(screen.getByLabelText("选择目标 安全响应群"));
  fireEvent.click(screen.getByRole("button", { name: "生成投递记录" }));

  expect(await screen.findByText("已生成 1 条投递记录")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "进入投递中心" })).toHaveAttribute(
    "href",
    "/deliveries?tab=records",
  );
  expect(fetchMock).toHaveBeenCalledWith(
    expect.stringContaining("/api/v1/announcements/runs/run-001/deliveries"),
    expect.objectContaining({
      method: "POST",
      body: JSON.stringify({
        target_ids: ["target-002"],
      }),
    }),
  );
});

test("delivery center target tab supports creating and editing targets", async () => {
  let targets = [
    {
      target_id: "target-001",
      name: "安全响应群",
      channel_type: "wecom",
      enabled: true,
      config_json: {
        webhook_url: "https://example.com/webhook",
        scene_names: ["announcement"],
      },
      config_summary: {
        webhook_url: "https://example.com/webhook",
        scene_names: ["announcement"],
      },
    },
  ];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.includes("/api/v1/platform/delivery-targets")) {
      if (init?.method === "POST") {
        targets = [
          ...targets,
          {
            target_id: "target-002",
            name: "邮件通知组",
            channel_type: "email",
            enabled: true,
            config_json: {
              recipients: ["soc@example.com"],
              scene_names: ["announcement"],
            },
            config_summary: {
              recipients: ["soc@example.com"],
              scene_names: ["announcement"],
            },
          },
        ];
        return mockJsonResponse({
          code: 0,
          message: "success",
          data: targets[1],
        });
      }

      if (init?.method === "PATCH") {
        targets = [
          {
            target_id: "target-001",
            name: "公告邮件组",
            channel_type: "email",
            enabled: false,
            config_json: {
              recipients: ["team@example.com"],
              scene_names: ["announcement"],
            },
            config_summary: {
              recipients: ["team@example.com"],
              scene_names: ["announcement"],
            },
          },
          targets[1]!,
        ];
        return mockJsonResponse({
          code: 0,
          message: "success",
          data: targets[0],
        });
      }

      return mockJsonResponse({
        code: 0,
        message: "success",
        data: targets,
      });
    }

    if (url.includes("/api/v1/platform/delivery-records")) {
      return mockJsonResponse({
        code: 0,
        message: "success",
        data: [],
      });
    }

    throw new Error(`未预期的请求: ${url}`);
  });

  vi.stubGlobal("fetch", fetchMock);

  renderPath("/deliveries");

  expect(await screen.findByText("安全响应群")).toBeInTheDocument();
  expect(screen.getByText(/wecom · 启用/)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "新建目标" })).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "投递记录" })).toHaveAttribute(
    "href",
    "/deliveries?tab=records",
  );

  fireEvent.click(screen.getByRole("button", { name: "新建目标" }));
  fireEvent.change(screen.getByLabelText("目标名称"), {
    target: { value: "邮件通知组" },
  });
  fireEvent.change(screen.getByLabelText("渠道类型"), {
    target: { value: "email" },
  });
  fireEvent.change(screen.getByLabelText("配置 JSON"), {
    target: {
      value: JSON.stringify(
        {
          recipients: ["soc@example.com"],
          scene_names: ["announcement"],
        },
        null,
        2,
      ),
    },
  });
  fireEvent.click(screen.getByRole("button", { name: "创建目标" }));

  expect(await screen.findByText("目标已保存")).toBeInTheDocument();
  expect(await screen.findByText("邮件通知组")).toBeInTheDocument();
  expect(fetchMock).toHaveBeenCalledWith(
    expect.stringContaining("/api/v1/platform/delivery-targets"),
    expect.objectContaining({
      method: "POST",
      body: JSON.stringify({
        name: "邮件通知组",
        channel_type: "email",
        enabled: true,
        config_json: {
          recipients: ["soc@example.com"],
          scene_names: ["announcement"],
        },
      }),
    }),
  );

  fireEvent.click(screen.getAllByRole("button", { name: "编辑目标" })[0]!);
  fireEvent.change(screen.getByLabelText("目标名称"), {
    target: { value: "公告邮件组" },
  });
  fireEvent.change(screen.getByLabelText("渠道类型"), {
    target: { value: "email" },
  });
  fireEvent.change(screen.getByLabelText("配置 JSON"), {
    target: {
      value: JSON.stringify(
        {
          recipients: ["team@example.com"],
          scene_names: ["announcement"],
        },
        null,
        2,
      ),
    },
  });
  fireEvent.click(screen.getByLabelText("启用目标"));
  fireEvent.click(screen.getByRole("button", { name: "保存修改" }));

  expect(await screen.findByText("公告邮件组")).toBeInTheDocument();
  expect(screen.getByText(/email · 禁用/)).toBeInTheDocument();
  expect(fetchMock).toHaveBeenCalledWith(
    expect.stringContaining("/api/v1/platform/delivery-targets/target-001"),
    expect.objectContaining({
      method: "PATCH",
      body: JSON.stringify({
        name: "公告邮件组",
        channel_type: "email",
        enabled: false,
        config_json: {
          recipients: ["team@example.com"],
          scene_names: ["announcement"],
        },
      }),
    }),
  );
});

test("delivery center records tab keeps filters in url and queries by scene status channel", async () => {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.includes("/api/v1/platform/delivery-targets")) {
      return mockJsonResponse({
        code: 0,
        message: "success",
        data: [],
      });
    }

    if (url.includes("/api/v1/platform/delivery-records")) {
      if (
        url.includes("scene_name=announcement") &&
        url.includes("status=prepared") &&
        url.includes("channel_type=wecom")
      ) {
        return mockJsonResponse({
          code: 0,
          message: "success",
          data: [
            {
              record_id: "record-001",
              scene_name: "announcement",
              source_ref_type: "announcement_run",
              source_ref_id: "run-001",
              target_id: "target-001",
              target_name: "安全响应群",
              channel_type: "wecom",
              status: "prepared",
              error_message: null,
              created_at: "2026-04-15T10:00:00+00:00",
              payload_summary: {
                title: "OpenSSL advisory",
              },
            },
          ],
        });
      }

      return mockJsonResponse({
        code: 0,
        message: "success",
        data: [
          {
            record_id: "record-001",
            scene_name: "announcement",
            source_ref_type: "announcement_run",
            source_ref_id: "run-001",
            target_id: "target-001",
            target_name: "安全响应群",
            channel_type: "wecom",
            status: "prepared",
            error_message: null,
            created_at: "2026-04-15T10:00:00+00:00",
            payload_summary: {
              title: "OpenSSL advisory",
            },
          },
        ],
      });
    }

    throw new Error(`未预期的请求: ${url}`);
  });

  vi.stubGlobal("fetch", fetchMock);

  renderPath("/deliveries?tab=records&scene_name=announcement&status=prepared&channel_type=wecom");

  expect(await screen.findByText("OpenSSL advisory")).toBeInTheDocument();
  expect(screen.getByText(/安全响应群 · announcement · prepared/)).toBeInTheDocument();
  expect(screen.getByLabelText("场景筛选")).toHaveValue("announcement");
  expect(screen.getByLabelText("状态筛选")).toHaveValue("prepared");
  expect(screen.getByLabelText("渠道筛选")).toHaveValue("wecom");
  expect(screen.getByRole("link", { name: "目标管理" })).toHaveAttribute(
    "href",
    "/deliveries",
  );

  fireEvent.change(screen.getByLabelText("渠道筛选"), {
    target: { value: "email" },
  });
  fireEvent.click(screen.getByRole("button", { name: "应用筛选" }));

  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining(
        "/api/v1/platform/delivery-records?scene_name=announcement&status=prepared&channel_type=email",
      ),
      expect.anything(),
    );
  });
});
