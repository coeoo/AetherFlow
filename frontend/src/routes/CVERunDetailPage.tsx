import { Link, useParams } from "react-router-dom";

import { PlaceholderPage } from "../components/layout/PlaceholderPage";

export function CVERunDetailPage() {
  const { runId = "未提供 runId" } = useParams();

  return (
    <PlaceholderPage
      eyebrow="CVE 结果页"
      title="CVE 运行详情"
      description={`当前路由已绑定运行详情路径，可承接 run_id = ${runId} 的证据页内容。`}
      status="详情路由已固定"
      actions={
        <div className="action-row">
          <Link className="action-link" to="/cve">
            返回工作台
          </Link>
        </div>
      }
      sections={[
        {
          title: "主结论卡",
          body: "后续首屏会优先展示补丁结论、可信原因和下一步建议，而不是原始 trace 字段。",
        },
        {
          title: "证据阅读区",
          body: "Patch、Fix Family、Trace 和 Diff Viewer 的结构位置已为后续实现预留。",
        },
      ]}
    />
  );
}
