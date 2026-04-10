import { PlaceholderPage } from "../components/layout/PlaceholderPage";
import { announcementMonitoringPlaceholder } from "../features/announcements/monitoring-placeholder";

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
