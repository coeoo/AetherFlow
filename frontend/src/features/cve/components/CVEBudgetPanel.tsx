import type { CVEBudgetUsage } from "../types";

type BudgetGroup = {
  pages?: CVEBudgetUsage;
  llm_calls?: CVEBudgetUsage;
  cross_domain?: CVEBudgetUsage;
};

type Props = {
  budget?: BudgetGroup;
};

function getUsagePercent(item?: CVEBudgetUsage) {
  if (!item || item.max <= 0) {
    return 0;
  }
  return Math.min(100, Math.round((item.used / item.max) * 100));
}

function getUsageTone(item?: CVEBudgetUsage) {
  const percent = getUsagePercent(item);
  if (percent > 80) {
    return "danger";
  }
  if (percent >= 50) {
    return "warn";
  }
  return "safe";
}

function BudgetRow({ label, item }: { label: string; item?: CVEBudgetUsage }) {
  const percent = getUsagePercent(item);
  const tone = getUsageTone(item);

  return (
    <article className="cve-budget-item">
      <div className="cve-trace-title-row">
        <strong>{label}</strong>
        <span>{item ? `${item.used}/${item.max}` : "暂无数据"}</span>
      </div>
      <div
        aria-valuemax={100}
        aria-valuemin={0}
        aria-valuenow={percent}
        className="cve-budget-track"
        role="progressbar"
      >
        <span
          className={`cve-budget-bar cve-budget-bar-${tone}`}
          style={{ width: `${percent}%` }}
        />
      </div>
    </article>
  );
}

export function CVEBudgetPanel({ budget }: Props) {
  if (!budget) {
    return null;
  }

  return (
    <section className="cve-panel">
      <div className="cve-panel-header">
        <p className="card-label">预算消耗</p>
        <h3>看这次搜索把页面、跨域和 LLM 配额花在了哪里</h3>
      </div>
      <div className="cve-budget-list">
        <BudgetRow label="页面预算" item={budget.pages} />
        <BudgetRow label="LLM 调用" item={budget.llm_calls} />
        <BudgetRow label="跨域跳转" item={budget.cross_domain} />
      </div>
    </section>
  );
}
