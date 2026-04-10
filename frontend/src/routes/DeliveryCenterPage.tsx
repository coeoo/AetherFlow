import { PlaceholderPage } from "../components/layout/PlaceholderPage";

export function DeliveryCenterPage() {
  return (
    <PlaceholderPage
      eyebrow="平台工具"
      title="投递中心"
      description="投递中心统一承接目标管理和投递记录，不拆成两个孤立的工具页。"
      status="工具页路由已固定"
      sections={[
        {
          title: "目标管理",
          body: "后续会接入目标列表、启停、测试发送和编辑抽屉，默认保留在同一页面体验中。",
        },
        {
          title: "投递记录",
          body: "后续通过 URL tab 持久化记录视图，承接筛选、失败重试和来源跳转。",
        },
      ]}
    />
  );
}
