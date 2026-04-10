import { Link } from "react-router-dom";

import { PlaceholderPage } from "../components/layout/PlaceholderPage";

export function HomePage() {
  return (
    <PlaceholderPage
      eyebrow="平台首页"
      title="平台首页"
      description="平台首页负责承接场景入口、最近任务、投递摘要和系统健康的首屏定位。"
      status="场景入口已固定"
      actions={
        <div className="action-row">
          <Link className="action-link" to="/cve">
            进入 CVE 补丁检索
          </Link>
          <Link className="action-link action-link-muted" to="/announcements">
            进入安全公告提取
          </Link>
        </div>
      }
      sections={[
        {
          title: "场景入口",
          body: "首页保持“CVE 补丁检索”和“安全公告提取”作为主视觉焦点，不把后台工具页抬成主入口。",
        },
        {
          title: "摘要区块",
          body: "最近任务、最近投递和健康摘要在 Phase 1 仅保留结构位置，后续由 Query 驱动真实数据。",
        },
      ]}
    />
  );
}
