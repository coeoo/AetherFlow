import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";

import { AppShell } from "../components/layout/AppShell";
import { PatchLookupResultPage } from "../features/cve/components/PatchLookupResultPage";
import {
  useCreateCveRun,
  useCveRunDetail,
  useCveRunHistory,
  usePatchContent,
} from "../features/cve/hooks";

type ResultSource = "history" | "fresh" | null;

const CVE_ID_PATTERN = /^CVE-\d{4}-\d{4,}$/;

function normalizeCveQuery(value: string | null) {
  return value?.trim().toUpperCase() ?? "";
}

function findLatestHistoryRun(query: string, runHistory: ReturnType<typeof useCveRunHistory>["data"]) {
  if (!query || !runHistory?.length) {
    return null;
  }

  return runHistory.find((run) => normalizeCveQuery(run.cve_id) === query) ?? null;
}

export function CVELookupPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const submittedQuery = normalizeCveQuery(searchParams.get("q"));
  const [queryInput, setQueryInput] = useState(submittedQuery);
  const [validationMessage, setValidationMessage] = useState<string | null>(null);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [resultSource, setResultSource] = useState<ResultSource>(null);
  const [selectedPatchId, setSelectedPatchId] = useState<string | null>(null);

  const historyQuery = useCveRunHistory(20);
  const createRun = useCreateCveRun();
  const matchedHistoryRun = findLatestHistoryRun(submittedQuery, historyQuery.data);
  const detailQuery = useCveRunDetail(selectedRunId, {
    refreshHistoryOnTerminal: resultSource === "fresh",
  });
  const detail = detailQuery.data ?? null;
  const patchContentQuery = usePatchContent(selectedRunId, selectedPatchId);

  useEffect(() => {
    setQueryInput(submittedQuery);
    setValidationMessage(null);
    setSelectedRunId(null);
    setResultSource(null);
    setSelectedPatchId(null);
  }, [submittedQuery]);

  useEffect(() => {
    if (!submittedQuery || historyQuery.isLoading || resultSource === "fresh") {
      return;
    }

    if (matchedHistoryRun) {
      if (selectedRunId !== matchedHistoryRun.run_id || resultSource !== "history") {
        setSelectedRunId(matchedHistoryRun.run_id);
        setResultSource("history");
      }
      return;
    }

    if (selectedRunId !== null || resultSource !== null) {
      setSelectedRunId(null);
      setResultSource(null);
    }
  }, [
    historyQuery.isLoading,
    matchedHistoryRun,
    resultSource,
    selectedRunId,
    submittedQuery,
  ]);

  useEffect(() => {
    if (!detail?.patches.length) {
      setSelectedPatchId(null);
      return;
    }

    if (selectedPatchId && detail.patches.some((patch) => patch.patch_id === selectedPatchId)) {
      return;
    }

    const firstAvailablePatch = detail.patches.find((patch) => patch.content_available);
    setSelectedPatchId(firstAvailablePatch?.patch_id ?? null);
  }, [detail, selectedPatchId]);

  function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const normalizedQuery = normalizeCveQuery(queryInput);
    if (!CVE_ID_PATTERN.test(normalizedQuery)) {
      setValidationMessage("请输入合法的 CVE 编号，例如 CVE-2024-3094");
      return;
    }

    setValidationMessage(null);
    setSelectedRunId(null);
    setResultSource(null);
    setSelectedPatchId(null);
    setSearchParams({ q: normalizedQuery });
  }

  function handleStartRun() {
    if (!CVE_ID_PATTERN.test(submittedQuery)) {
      return;
    }

    createRun.mutate(submittedQuery, {
      onSuccess: (createdRun) => {
        setSelectedPatchId(null);
        setSelectedRunId(createdRun.run_id);
        setResultSource("fresh");
      },
    });
  }

  const loadingResult =
    Boolean(submittedQuery) &&
    (historyQuery.isLoading || (Boolean(selectedRunId) && detailQuery.isLoading && !detail));
  const isRefreshing = Boolean(detail) && detailQuery.isFetching && !detailQuery.isLoading;
  const canStartRun =
    Boolean(submittedQuery) && CVE_ID_PATTERN.test(submittedQuery) && !createRun.isPending;

  return (
    <AppShell
      eyebrow="Patch 检索"
      title="Patch 检索"
      description="以漏洞编号作为入口，优先回看历史 Patch 结果；只有在你主动确认时，才发起一次新的检索。"
    >
      <section className="cve-panel cve-panel-featured patch-query-panel">
        <form className="cve-panel-header" onSubmit={handleSubmit}>
          <p className="card-label">查询入口</p>
          <h2>先看历史，再决定是否重新检索</h2>
          <p className="card-copy">
            当前页面统一以 <strong>Patch 结果中心</strong> 作为主视图。
            输入使用 <strong>漏洞编号</strong> 作为检索入口，但会优先展示已有历史结果。
          </p>
          <div className="patch-query-row">
            <label className="cve-field" htmlFor="patch-query-input">
              <span className="cve-field-label">漏洞编号</span>
              <input
                id="patch-query-input"
                className="cve-input"
                value={queryInput}
                onChange={(event) => setQueryInput(event.target.value)}
                placeholder="CVE-2024-3094"
              />
            </label>
            <div className="action-row patch-query-actions">
              <button className="action-link action-link-obsidian" type="submit">
                查看历史结果
              </button>
            </div>
          </div>
          {validationMessage ? <p className="cve-error-copy">{validationMessage}</p> : null}
        </form>
      </section>

      <PatchLookupResultPage
        query={submittedQuery}
        detail={detail}
        historyRuns={historyQuery.data ?? []}
        resultSource={resultSource}
        loadingResult={loadingResult}
        isRefreshing={isRefreshing}
        canStartRun={canStartRun}
        onStartRun={handleStartRun}
        selectedPatchId={selectedPatchId}
        onSelectPatch={setSelectedPatchId}
        patchContent={patchContentQuery.data?.content ?? null}
        patchLoading={patchContentQuery.isLoading}
        patchErrorMessage={
          patchContentQuery.error instanceof Error ? patchContentQuery.error.message : null
        }
      />
    </AppShell>
  );
}
