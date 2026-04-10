import { Link, useSearchParams } from "react-router-dom";

import { PlaceholderPage } from "../components/layout/PlaceholderPage";
import { announcementMonitoringPlaceholder } from "../features/announcements/monitoring-placeholder";

export function AnnouncementWorkbenchPage() {
  const [searchParams] = useSearchParams();
  const activeTab = searchParams.get("tab");
  const isMonitoringTab = activeTab === "monitoring";

  return (
    <PlaceholderPage
      eyebrow="安全公告场景"
      title="安全公告工作台"
      description={
        isMonitoringTab
          ? announcementMonitoringPlaceholder.description
          : "工作台页面承接 URL/正文双入口、运行态展示和情报包预览。"
      }
      status={isMonitoringTab ? announcementMonitoringPlaceholder.status : "工作台壳已就绪"}
      actions={
        <div className="action-row">
          <Link className="action-link" to="/announcements?tab=monitoring">
            查看监控批次
          </Link>
          <Link className="action-link action-link-muted" to="/announcements/sources">
            管理监控源
          </Link>
        </div>
      }
      sections={
        isMonitoringTab
          ? [...announcementMonitoringPlaceholder.sections]
          : [
              {
                title: "输入模式",
                body: "后续将在这里承接 URL 提取和正文提取两种模式，并保持未提交草稿切换时不丢失。",
              },
              {
                title: "结果预览",
                body: "当前仅固定情报包预览区块位置，后续通过 Query 展示运行态、摘要和重复提示。",
              },
            ]
      }
    />
  );
}
