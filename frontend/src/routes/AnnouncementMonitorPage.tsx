import { PlaceholderPage } from "../components/layout/PlaceholderPage";

export const announcementMonitoringPlaceholder = {
  description: "当前工作台正在复用监控批次占位模块，后续可平滑拆分为独立监控页。",
  status: "监控批次视图已接入",
  sections: [
    {
      title: "批次列表",
      body: "后续会展示抓取批次、新增条目数和触发的提取运行数量。",
    },
    {
      title: "详情联动",
      body: "批次与单文档 run 会保持分层展示，避免把抓取批次误当成结果详情页。",
    },
  ],
} as const;

export function AnnouncementMonitorPage() {
  return (
    <PlaceholderPage
      eyebrow="公告监控"
      title="公告监控批次"
      description="该模块已预留文件入口，后续可从工作台中的 monitoring tab 平滑拆分为独立场景页。"
      status={announcementMonitoringPlaceholder.status}
      sections={announcementMonitoringPlaceholder.sections}
    />
  );
}
