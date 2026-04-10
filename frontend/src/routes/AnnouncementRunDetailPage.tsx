import { Link, useParams } from "react-router-dom";

import { PlaceholderPage } from "../components/layout/PlaceholderPage";

export function AnnouncementRunDetailPage() {
  const { runId = "未提供 runId" } = useParams();

  return (
    <PlaceholderPage
      eyebrow="公告结果页"
      title="安全公告情报包详情"
      description={`当前详情路由已经预留情报包结果页，可承接 run_id = ${runId} 的结构化结果。`}
      status="结果详情路由已固定"
      actions={
        <div className="action-row">
          <Link className="action-link" to="/announcements">
            返回工作台
          </Link>
          <Link className="action-link action-link-muted" to={`/announcements/runs/${runId}#delivery`}>
            跳到投递区块
          </Link>
        </div>
      }
      sections={[
        {
          title: "分析师摘要",
          body: "页面将保持“摘要先行”，优先展示风险级别、置信度和受影响对象，而不是原始材料全文。",
        },
        {
          title: "投递区块",
          body: "当前占位已为 #delivery 区域预留结构位置，后续接入推荐发送、目标摘要和最近记录。",
        },
      ]}
    />
  );
}
