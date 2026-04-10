import { Link } from "react-router-dom";

import { PlaceholderPage } from "../components/layout/PlaceholderPage";

export function TaskCenterPage() {
  return (
    <PlaceholderPage
      eyebrow="平台工具"
      title="平台任务中心"
      description="任务中心用于查看任务状态、attempt 轨迹和平台级重试，不替代场景结果页。"
      status="任务排障入口已固定"
      actions={
        <div className="action-row">
          <Link className="action-link" to="/system/health">
            查看系统状态
          </Link>
        </div>
      }
      sections={[
        {
          title: "任务列表",
          body: "后续会按运行中和失败优先展示任务，并支持按场景、状态和触发方式筛选。",
        },
        {
          title: "Attempt 轨迹",
          body: "详情抽屉和时间线结构已预留，后续承接重试记录与关联 run 跳转。",
        },
      ]}
    />
  );
}
