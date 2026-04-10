import { Link } from "react-router-dom";

import { PlaceholderPage } from "../components/layout/PlaceholderPage";

export function CVELookupPage() {
  return (
    <PlaceholderPage
      eyebrow="CVE 场景"
      title="CVE 检索工作台"
      description="工作台页面固定“输入 -> 运行状态 -> 结论摘要 -> 详情入口”的页面节奏。"
      status="工作台壳已就绪"
      actions={
        <div className="action-row">
          <Link className="action-link" to="/cve/runs/demo-run">
            查看示例详情
          </Link>
        </div>
      }
      sections={[
        {
          title: "输入区",
          body: "后续在该区块承接 CVE 编号输入、格式校验和运行创建动作。",
        },
        {
          title: "结论摘要",
          body: "当前仅固定卡片位置，后续会通过 Query 展示运行状态、可信原因和详情跳转。",
        },
      ]}
    />
  );
}
