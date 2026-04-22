import type {
  CVEFrontierStatus,
  CVESearchDecision,
  CVESearchEdge,
  CVESearchNode,
} from "../types";

type Props = {
  nodes: CVESearchNode[];
  edges: CVESearchEdge[];
  decisions: CVESearchDecision[];
  frontierStatus?: CVEFrontierStatus;
};

const PAGE_ROLE_LABELS: Record<string, string> = {
  advisory_page: "安全公告",
  tracker_page: "安全追踪器",
  commit_page: "代码提交",
  download_page: "下载页",
};

function getPageRoleLabel(pageRole: string | null) {
  if (!pageRole) {
    return "未分类";
  }
  return PAGE_ROLE_LABELS[pageRole] ?? pageRole;
}

function getNodeTone(pageRole: string | null) {
  switch (pageRole) {
    case "advisory_page":
      return "advisory";
    case "tracker_page":
      return "tracker";
    case "commit_page":
      return "commit";
    case "download_page":
      return "download";
    default:
      return "neutral";
  }
}

function getHostLabel(url: string) {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

export function CVESearchGraphPanel({
  nodes,
  edges,
  decisions,
  frontierStatus,
}: Props) {
  const nodeById = new Map(nodes.map((node) => [node.node_id, node]));
  const decisionsByNodeId = new Map<string, CVESearchDecision[]>();

  decisions.forEach((decision) => {
    if (!decision.node_id) {
      return;
    }
    const bucket = decisionsByNodeId.get(decision.node_id) ?? [];
    bucket.push(decision);
    decisionsByNodeId.set(decision.node_id, bucket);
  });

  const sortedNodes = [...nodes].sort((left, right) => {
    if (left.depth !== right.depth) {
      return left.depth - right.depth;
    }
    return left.url.localeCompare(right.url);
  });

  return (
    <section className="cve-panel">
      <div className="cve-panel-header">
        <p className="card-label">搜索图</p>
        <h3>页面角色、跨域边和 Agent 决策都在这里</h3>
      </div>
      {frontierStatus ? (
        <div className="summary-grid">
          <article className="summary-inline-item">
            <strong>节点总数</strong>
            <span>{frontierStatus.total_nodes}</span>
          </article>
          <article className="summary-inline-item">
            <strong>最大深度</strong>
            <span>{frontierStatus.max_depth}</span>
          </article>
          <article className="summary-inline-item">
            <strong>活跃节点</strong>
            <span>{frontierStatus.active_node_count}</span>
          </article>
        </div>
      ) : null}
      <div className="cve-search-graph-list">
        {sortedNodes.map((node) => {
          const nodeDecisions = decisionsByNodeId.get(node.node_id) ?? [];
          return (
            <article
              className={`cve-search-node cve-search-node-${getNodeTone(node.page_role)}`}
              key={node.node_id}
              style={{ marginLeft: `${node.depth * 20}px` }}
              title={node.url}
            >
              <div className="cve-trace-title-row">
                <strong>{getHostLabel(node.url)}</strong>
                <span className={`cve-status-chip cve-status-chip-${node.fetch_status}`}>
                  {node.fetch_status}
                </span>
              </div>
              <div className="stack-xs">
                <span className="cve-field-label">{getPageRoleLabel(node.page_role)}</span>
                <span className="card-copy">{node.url}</span>
              </div>
              {nodeDecisions.length > 0 ? (
                <div className="cve-search-decision-list">
                  {nodeDecisions.map((decision, index) => (
                    <span
                      className={`cve-search-decision-chip${
                        decision.validated ? " cve-search-decision-chip-valid" : ""
                      }`}
                      key={`${node.node_id}:${decision.decision_type}:${index}`}
                    >
                      {decision.decision_type}
                    </span>
                  ))}
                </div>
              ) : null}
            </article>
          );
        })}
      </div>
      {edges.length > 0 ? (
        <div className="cve-search-edge-list">
          {edges.map((edge, index) => {
            const fromNode = nodeById.get(edge.from_node_id);
            const toNode = nodeById.get(edge.to_node_id);
            const isCrossDomain = fromNode?.host && toNode?.host && fromNode.host !== toNode.host;
            return (
              <div className="cve-search-edge-row" key={`${edge.from_node_id}:${edge.to_node_id}:${index}`}>
                <span
                  className={`cve-search-edge-line${
                    isCrossDomain ? " cve-search-edge-line-cross" : ""
                  }`}
                />
                <span className="card-copy">
                  {fromNode ? getHostLabel(fromNode.url) : edge.from_node_id}
                  {" -> "}
                  {toNode ? getHostLabel(toNode.url) : edge.to_node_id}
                  {` · ${edge.selected_by}`}
                </span>
              </div>
            );
          })}
        </div>
      ) : null}
    </section>
  );
}
