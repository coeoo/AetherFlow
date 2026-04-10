import { render, screen } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router-dom";

import { routes } from "../app/router";

function renderPath(path: string) {
  const router = createMemoryRouter(routes, {
    initialEntries: [path],
    future: {
      v7_startTransition: true,
    },
  });

  render(
    <RouterProvider
      router={router}
      future={{
        v7_startTransition: true,
      }}
    />,
  );
}

test.each([
  ["/", "平台首页"],
  ["/cve", "CVE 检索工作台"],
  ["/cve/runs/run-001", "CVE 运行详情"],
  ["/announcements", "安全公告工作台"],
  ["/announcements?tab=monitoring", "安全公告工作台"],
  ["/announcements/sources", "监控源管理"],
  ["/announcements/runs/run-002", "安全公告情报包详情"],
  ["/deliveries", "投递中心"],
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

test("reuses the monitoring placeholder content for /announcements?tab=monitoring", async () => {
  renderPath("/announcements?tab=monitoring");

  expect(await screen.findByText("批次列表")).toBeInTheDocument();
  expect(screen.getByText("当前工作台正在复用监控批次占位模块，后续可平滑拆分为独立监控页。")).toBeInTheDocument();
});
