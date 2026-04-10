import { Link } from "react-router-dom";

import { PlaceholderPage } from "../components/layout/PlaceholderPage";

export function SystemHealthPage() {
  return (
    <PlaceholderPage
      eyebrow="平台工具"
      title="系统状态"
      description="系统状态页负责承接健康摘要、关键依赖状态和运行级告警，不演变成监控大屏。"
      status="健康页路由已固定"
      actions={
        <div className="action-row">
          <Link className="action-link" to="/system/tasks">
            进入任务中心
          </Link>
        </div>
      }
      sections={[
        {
          title: "核心状态卡",
          body: "后续通过 Query 展示 API、Database、Worker 和 Scheduler 的健康摘要。",
        },
        {
          title: "运行告警",
          body: "页面会保留跳转任务中心的辅助入口，但不会在首屏堆叠复杂图表和日志墙。",
        },
      ]}
    />
  );
}
