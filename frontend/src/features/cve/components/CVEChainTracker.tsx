import type { CVEChainStep, CVEChainSummary } from "../types";

type Props = {
  chains: CVEChainSummary[];
};

const CHAIN_TYPE_LABELS: Record<string, string> = {
  advisory_to_patch: "公告→补丁",
  tracker_to_commit: "追踪器→提交",
  mailing_list_to_fix: "邮件列表→修复",
};

const PAGE_ROLE_LABELS: Record<string, string> = {
  advisory_page: "安全公告",
  tracker_page: "安全追踪器",
  commit_page: "代码提交",
  download_page: "下载页",
  mailing_list_page: "邮件列表",
  bugtracker_page: "Bug 追踪器",
  pull_request_page: "Pull Request",
  repository_page: "代码仓库",
};

function getChainTypeLabel(chainType: string) {
  return CHAIN_TYPE_LABELS[chainType] ?? chainType;
}

function getPageRoleLabel(pageRole: string) {
  return PAGE_ROLE_LABELS[pageRole] ?? pageRole;
}

function getHostLabel(url: string) {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

function isCrossDomainStep(previousStep: CVEChainStep | undefined, currentStep: CVEChainStep) {
  if (!previousStep) {
    return false;
  }
  return getHostLabel(previousStep.url) !== getHostLabel(currentStep.url);
}

export function CVEChainTracker({ chains }: Props) {
  return (
    <section className="cve-panel">
      <div className="cve-panel-header">
        <p className="card-label">Agent 链路追踪</p>
        <h3>浏览器 Agent 是怎么一路走到补丁页面的</h3>
      </div>
      <div className="cve-chain-list">
        {chains.map((chain) => (
          <article className="cve-chain-card" key={chain.chain_id}>
            <div className="cve-trace-title-row">
              <strong>{getChainTypeLabel(chain.chain_type)}</strong>
              <span className={`cve-status-chip cve-status-chip-${chain.status}`}>
                {chain.status}
              </span>
            </div>
            <div className="cve-chain-timeline">
              {chain.steps.map((step, index) => {
                const previousStep = index > 0 ? chain.steps[index - 1] : undefined;
                return (
                  <div className="cve-chain-step" key={`${chain.chain_id}:${step.url}:${index}`}>
                    {index > 0 ? (
                      <div
                        aria-hidden="true"
                        className={`cve-chain-connector${
                          isCrossDomainStep(previousStep, step)
                            ? " cve-chain-connector-cross"
                            : ""
                        }`}
                      />
                    ) : null}
                    <button className="cve-chain-step-button" title={step.url} type="button">
                      <span className={`cve-role-dot cve-role-dot-${step.page_role || "unknown"}`} />
                      <span className="cve-chain-step-copy">
                        <strong>{getPageRoleLabel(step.page_role)}</strong>
                        <span>{getHostLabel(step.url)}</span>
                      </span>
                    </button>
                  </div>
                );
              })}
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}
