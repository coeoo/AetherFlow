import { useState } from "react";
import { Link } from "react-router-dom";

import { AppShell } from "../components/layout/AppShell";
import { CVERunHistoryList } from "../features/cve/components/CVERunHistoryList";
import { useCreateCveRun, useCveRunDetail, useCveRunHistory } from "../features/cve/hooks";
import { getCvePhaseLabel, getCveStopReasonLabel } from "../features/cve/presentation";

export function CVELookupPage() {
  const [query, setQuery] = useState("CVE-2024-3094");
  const [validationMessage, setValidationMessage] = useState<string | null>(null);
  const [activeRunId, setActiveRunId] = useState<string | null>(null);
  const createRun = useCreateCveRun();
  const historyQuery = useCveRunHistory();
  const detailQuery = useCveRunDetail(activeRunId, { refreshHistoryOnTerminal: true });
  const detail = detailQuery.data;

  function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!/^CVE-\d{4}-\d{4,}$/.test(query.trim())) {
      setValidationMessage("请输入合法的 CVE 编号，例如 CVE-2024-3094");
      return;
    }

    setValidationMessage(null);
    createRun.mutate(query.trim(), {
      onSuccess: (run) => {
        setActiveRunId(run.run_id);
      },
    });
  }

  return (
    <AppShell
      eyebrow="CVE 场景"
      title="CVE 检索工作台"
      description="输入一个 CVE 编号，先看结论，再在详情页里继续阅读证据与 Diff。"
      actions={
        detail ? (
          <div className="action-row">
            <Link className="action-link action-link-obsidian" to={`/cve/runs/${detail.run_id}`}>
              查看详情
            </Link>
          </div>
        ) : null
      }
    >
      <section className="cve-workbench-grid">
        <form className="cve-panel cve-panel-featured" onSubmit={handleSubmit}>
          <div className="cve-panel-header">
            <p className="card-label">输入区</p>
            <h2>开始一次补丁检索</h2>
          </div>
          <label className="cve-field" htmlFor="cve-id-input">
            <span className="cve-field-label">CVE 编号</span>
            <input
              id="cve-id-input"
              className="cve-input"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="CVE-2024-3094"
            />
          </label>
          {validationMessage ? <p className="cve-error-copy">{validationMessage}</p> : null}
          <div className="action-row">
            <button className="action-link action-link-obsidian" disabled={createRun.isPending} type="submit">
              {createRun.isPending ? "创建中…" : "开始检索"}
            </button>
          </div>
        </form>

        <section className="cve-panel">
          <div className="cve-panel-header">
            <p className="card-label">运行状态</p>
            <h2>当前阶段与最近进展</h2>
          </div>
          <p className={`status-pill status-pill-${detail?.status ?? "queued"}`}>{detail?.status ?? "idle"}</p>
          <p className="card-copy">当前阶段：{detail ? getCvePhaseLabel(detail.phase) : "尚未开始"}</p>
          <div className="cve-progress-copy">
            {detail?.recent_progress?.length ? (
              detail.recent_progress.map((item) => (
                <article key={`${item.step}-${item.detail ?? "none"}`} className="cve-inline-progress">
                  <strong>{item.label}</strong>
                  <span>{item.detail ?? "无明细"}</span>
                </article>
              ))
            ) : (
              <p className="card-copy">创建 run 后，这里会滚动展示最近 1 到 3 条关键进展。</p>
            )}
          </div>
        </section>

        <section className="cve-panel cve-verdict-card">
          <div className="cve-panel-header">
            <p className="card-label">结论摘要</p>
            <h2>{detail?.summary.patch_found ? "已命中补丁" : "等待结论形成"}</h2>
          </div>
          <p className="card-copy">
            主证据：{detail?.summary.primary_patch_url ?? "运行完成后会在这里显示最可信的 patch URL"}
          </p>
          <p className="card-copy">
            停止原因：{getCveStopReasonLabel(detail?.stop_reason ?? null, detail?.status ?? "running")}
          </p>
          {detail ? (
            <div className="action-row">
              <Link className="action-link action-link-obsidian" to={`/cve/runs/${detail.run_id}`}>
                查看详情
              </Link>
            </div>
          ) : null}
        </section>

        <CVERunHistoryList runs={historyQuery.data ?? []} />
      </section>
    </AppShell>
  );
}
