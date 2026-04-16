import { Link, useSearchParams } from "react-router-dom";

import { AppShell } from "../components/layout/AppShell";
import {
  useDeliveryRecords,
  useDeliveryTargets,
  useUpdateDeliveryTarget,
} from "../features/deliveries/hooks";

export function DeliveryCenterPage() {
  const [searchParams] = useSearchParams();
  const activeTab = searchParams.get("tab") === "records" ? "records" : "targets";
  const statusFilter = searchParams.get("status");
  const targetsQuery = useDeliveryTargets();
  const recordsQuery = useDeliveryRecords("announcement", activeTab === "records" ? statusFilter : null);
  const updateTarget = useUpdateDeliveryTarget();
  const targets = targetsQuery.data ?? [];
  const records = recordsQuery.data ?? [];

  return (
    <AppShell
      eyebrow="平台工具"
      title="投递中心"
      description="投递中心统一承接目标管理和投递记录，不拆成两个孤立的工具页。"
      actions={
        <div className="action-row">
          <Link className="action-link" to="/announcements">
            返回安全公告工作台
          </Link>
        </div>
      }
    >
      <section className="cve-workbench-grid">
        <section className="cve-panel cve-panel-featured">
          <div className="cve-panel-header">
            <p className="card-label">当前阶段</p>
            <h2>{activeTab === "records" ? "公告记录已接入" : "目标视图已接入"}</h2>
          </div>
          <p className="card-copy">
            当前页先把投递中心拆成目标管理与投递记录两个真实视图，后续再补测试发送和重试动作。
          </p>
          <div className="action-row">
            <Link
              className={activeTab === "targets" ? "action-link action-link-obsidian" : "action-link"}
              to="/deliveries"
            >
              目标管理
            </Link>
            <Link
              className={activeTab === "records" ? "action-link action-link-obsidian" : "action-link"}
              to="/deliveries?tab=records"
            >
              投递记录
            </Link>
          </div>
          <p className="card-copy">
            {activeTab === "records" ? `记录数量：${records.length}` : `目标数量：${targets.length}`}
          </p>
        </section>

        <section className="cve-panel">
          <div className="cve-panel-header">
            <p className="card-label">目标管理</p>
            <h2>{activeTab === "targets" ? "当前目标列表" : "目标能力预留"}</h2>
          </div>
          {activeTab === "targets" ? (
            <>
              {targetsQuery.isLoading ? <p className="card-copy">正在加载投递目标…</p> : null}
              {!targetsQuery.isLoading && !targets.length ? (
                <p className="card-copy">当前还没有投递目标。</p>
              ) : null}
              {targets.map((target) => (
                <article key={target.target_id} className="cve-inline-progress">
                  <strong>{target.name}</strong>
                  <span>
                    {target.channel_type} · {target.enabled ? "启用" : "禁用"}
                  </span>
                  <div className="action-row">
                    <button
                      className="action-link action-link-muted"
                      disabled={updateTarget.isPending}
                      type="button"
                      onClick={() => {
                        updateTarget.mutate({
                          target_id: target.target_id,
                          enabled: !target.enabled,
                        });
                      }}
                    >
                      {target.enabled ? "停用目标" : "启用目标"}
                    </button>
                  </div>
                </article>
              ))}
              {updateTarget.data ? <p className="card-copy">目标状态已更新</p> : null}
            </>
          ) : (
            <p className="card-copy">目标列表保留在 `targets` 视图，后续补启停开关、测试发送和编辑抽屉。</p>
          )}
        </section>

        <section className="cve-panel">
          <div className="cve-panel-header">
            <p className="card-label">投递记录</p>
            <h2>公告场景记录</h2>
          </div>
          {activeTab === "records" ? (
            <>
              <div className="action-row">
                <Link
                  className={statusFilter === null ? "action-link action-link-obsidian" : "action-link"}
                  to="/deliveries?tab=records"
                >
                  全部状态
                </Link>
                <Link
                  className={statusFilter === "prepared" ? "action-link action-link-obsidian" : "action-link"}
                  to="/deliveries?tab=records&status=prepared"
                >
                  仅看 prepared
                </Link>
              </div>
              {recordsQuery.isLoading ? <p className="card-copy">正在加载投递记录…</p> : null}
              {!recordsQuery.isLoading && !records.length ? (
                <p className="card-copy">当前还没有投递记录。</p>
              ) : null}
              {records.map((record) => (
                <article key={record.record_id} className="cve-inline-progress">
                  <strong>{String(record.payload_summary.title ?? "未命名投递")}</strong>
                  <span>
                    {record.target_name} · {record.scene_name} · {record.status}
                  </span>
                </article>
              ))}
            </>
          ) : (
            <p className="card-copy">切换到 `records` 视图即可查看公告场景的投递留痕。</p>
          )}
        </section>
      </section>
    </AppShell>
  );
}
