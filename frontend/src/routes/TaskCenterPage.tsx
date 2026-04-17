import { useState } from "react";
import { Link } from "react-router-dom";

import { AppShell } from "../components/layout/AppShell";
import { usePlatformTaskDetail, usePlatformTasks, useRetryPlatformTask } from "../features/tasks/hooks";
import { getTaskPrimaryCopy, getTaskRunLink } from "../features/tasks/presentation";

export function TaskCenterPage() {
  const [sceneFilter, setSceneFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [triggerFilter, setTriggerFilter] = useState<string>("all");
  const [selectedJobId, setSelectedJobId] = useState<string | null>(null);
  const [saveMessage, setSaveMessage] = useState<string | null>(null);

  const filters = {
    scene_name: sceneFilter === "all" ? null : sceneFilter,
    status: statusFilter === "all" ? null : statusFilter,
    trigger_kind: triggerFilter === "all" ? null : triggerFilter,
    page: 1,
    page_size: 20,
  };
  const tasksQuery = usePlatformTasks(filters);
  const taskDetailQuery = usePlatformTaskDetail(selectedJobId);
  const retryTask = useRetryPlatformTask();
  const tasks = tasksQuery.data?.items ?? [];
  const selectedDetail = taskDetailQuery.data;

  async function handleRetry(jobId: string) {
    setSaveMessage(null);
    try {
      await retryTask.mutateAsync(jobId);
      setSaveMessage("任务已重新排队");
    } catch (error) {
      setSaveMessage(error instanceof Error ? error.message : "任务重排失败");
    }
  }

  return (
    <AppShell
      eyebrow="平台工具"
      title="平台任务中心"
      description="任务中心用于查看任务状态、attempt 轨迹和平台级重试，不替代场景结果页。"
      actions={
        <div className="action-row">
          <Link className="action-link" to="/system/health">
            查看系统状态
          </Link>
        </div>
      }
    >
      <section className="cve-workbench-grid">
        <section className="cve-panel cve-panel-featured">
          <div className="cve-panel-header">
            <p className="card-label">任务筛选</p>
            <h2>平台任务列表</h2>
          </div>
          <div className="task-filter-grid">
            <label className="stack-xs">
              <span>场景</span>
              <select value={sceneFilter} onChange={(event) => setSceneFilter(event.target.value)}>
                <option value="all">全部</option>
                <option value="cve">cve</option>
                <option value="announcement">announcement</option>
              </select>
            </label>
            <label className="stack-xs">
              <span>状态</span>
              <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}>
                <option value="all">全部</option>
                <option value="queued">queued</option>
                <option value="running">running</option>
                <option value="succeeded">succeeded</option>
                <option value="failed">failed</option>
              </select>
            </label>
            <label className="stack-xs">
              <span>触发方式</span>
              <select value={triggerFilter} onChange={(event) => setTriggerFilter(event.target.value)}>
                <option value="all">全部</option>
                <option value="manual">manual</option>
                <option value="monitor">monitor</option>
              </select>
            </label>
          </div>
          {saveMessage ? <p className="card-copy">{saveMessage}</p> : null}
          {tasksQuery.isLoading ? <p className="card-copy">正在加载任务列表…</p> : null}
          {!tasksQuery.isLoading && !tasks.length ? <p className="card-copy">当前还没有平台任务。</p> : null}
          <div className="stack-sm">
            {tasks.map((task) => (
              <article key={task.job_id} className="summary-inline-item">
                <strong>{task.job_id}</strong>
                <span>
                  {task.scene_name} · {task.status}
                </span>
                <span>{getTaskPrimaryCopy(task)}</span>
                <div className="action-row">
                  <button
                    className="action-link action-link-muted"
                    type="button"
                    onClick={() => setSelectedJobId(task.job_id)}
                  >
                    查看详情
                  </button>
                  {task.status === "failed" ? (
                    <button
                      className="action-link action-link-obsidian"
                      type="button"
                      onClick={() => {
                        void handleRetry(task.job_id);
                      }}
                    >
                      重新排队
                    </button>
                  ) : null}
                </div>
              </article>
            ))}
          </div>
        </section>

        <section className="cve-panel">
          <div className="cve-panel-header">
            <p className="card-label">任务详情</p>
            <h2>{selectedDetail ? selectedDetail.job_id : "选择一条任务查看详情"}</h2>
          </div>
          {taskDetailQuery.isLoading ? <p className="card-copy">正在加载任务详情…</p> : null}
          {!selectedDetail && !taskDetailQuery.isLoading ? (
            <p className="card-copy">点击左侧任务即可查看 scene_run、payload 摘要和 attempt 时间线。</p>
          ) : null}
          {selectedDetail ? (
            <div className="stack-sm">
              <p className="card-copy">scene_run_id：{selectedDetail.scene_run_id ?? "未绑定"}</p>
              <p className="card-copy">当前状态：{selectedDetail.status}</p>
              <p className="card-copy">输入摘要：{getTaskPrimaryCopy(selectedDetail)}</p>
              {getTaskRunLink(selectedDetail) ? (
                <div className="action-row">
                  <Link className="action-link action-link-muted" to={getTaskRunLink(selectedDetail)!}>
                    查看关联结果
                  </Link>
                </div>
              ) : null}
              <div className="stack-sm">
                {selectedDetail.attempts.map((attempt) => (
                  <article key={attempt.attempt_id} className="summary-inline-item">
                    <strong>Attempt #{attempt.attempt_no}</strong>
                    <span>
                      {attempt.status} · {attempt.worker_name ?? "unknown-worker"}
                    </span>
                    <span>{attempt.error_message ?? "无错误信息"}</span>
                  </article>
                ))}
              </div>
            </div>
          ) : null}
        </section>
      </section>
    </AppShell>
  );
}
