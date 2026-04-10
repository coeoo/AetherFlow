import { Link } from "react-router-dom";

import { PlaceholderPage } from "../components/layout/PlaceholderPage";

export function AnnouncementSourcesPage() {
  return (
    <PlaceholderPage
      eyebrow="公告监控"
      title="监控源管理"
      description="该页面为监控源列表、启停、试跑和编辑抽屉预留稳定路由入口。"
      status="源管理路由已固定"
      actions={
        <div className="action-row">
          <Link className="action-link" to="/announcements">
            返回手动提取
          </Link>
          <Link className="action-link action-link-muted" to="/announcements?tab=monitoring">
            查看批次结果
          </Link>
        </div>
      }
      sections={[
        {
          title: "源列表",
          body: "后续将承接首批监控源卡片、启停动作和最近一次抓取摘要。",
        },
        {
          title: "编辑抽屉",
          body: "当前占位用于固定 create/edit 复用结构，后续接入动态表单和校验。",
        },
      ]}
    />
  );
}
