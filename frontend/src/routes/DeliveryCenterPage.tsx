import { useEffect, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { AppShell } from "../components/layout/AppShell";
import {
  useCreateDeliveryTarget,
  useDeliveryRecords,
  useDeliveryTargets,
  useUpdateDeliveryTarget,
} from "../features/deliveries/hooks";
import type { DeliveryRecordFilters, DeliveryTargetView } from "../features/deliveries/types";

type DeliveryTargetFormState = {
  name: string;
  channelType: string;
  enabled: boolean;
  configText: string;
};

const EMPTY_TARGET_FORM: DeliveryTargetFormState = {
  name: "",
  channelType: "wecom",
  enabled: true,
  configText: "{\n  \"scene_names\": [\n    \"announcement\"\n  ]\n}",
};

export function DeliveryCenterPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const activeTab = searchParams.get("tab") === "records" ? "records" : "targets";
  const urlRecordFilters = getRecordFiltersFromSearchParams(searchParams);
  const targetsQuery = useDeliveryTargets();
  const recordsQuery = useDeliveryRecords(
    activeTab === "records"
      ? urlRecordFilters
      : {
          scene_name: "announcement",
          status: null,
          channel_type: null,
        },
  );
  const createTarget = useCreateDeliveryTarget();
  const updateTarget = useUpdateDeliveryTarget();
  const targets = targetsQuery.data ?? [];
  const records = recordsQuery.data ?? [];

  const [editingTargetId, setEditingTargetId] = useState<string | null>(null);
  const [formState, setFormState] = useState<DeliveryTargetFormState>(EMPTY_TARGET_FORM);
  const [recordFilters, setRecordFilters] = useState<DeliveryRecordFilters>(urlRecordFilters);
  const [formError, setFormError] = useState<string | null>(null);
  const [saveMessage, setSaveMessage] = useState<string | null>(null);

  const isEditing = editingTargetId !== null;
  const isSaving = createTarget.isPending || updateTarget.isPending;

  useEffect(() => {
    if (editingTargetId === null) {
      return;
    }

    const target = targets.find((item) => item.target_id === editingTargetId);
    if (!target) {
      return;
    }

    setFormState(toTargetFormState(target));
  }, [editingTargetId, targets]);

  useEffect(() => {
    setRecordFilters(getRecordFiltersFromSearchParams(searchParams));
  }, [searchParams]);

  function resetEditor() {
    setEditingTargetId(null);
    setFormState(EMPTY_TARGET_FORM);
    setFormError(null);
  }

  function openCreateEditor() {
    setEditingTargetId(null);
    setFormState(EMPTY_TARGET_FORM);
    setFormError(null);
    setSaveMessage(null);
  }

  function openEditEditor(target: DeliveryTargetView) {
    setEditingTargetId(target.target_id);
    setFormState(toTargetFormState(target));
    setFormError(null);
    setSaveMessage(null);
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError(null);
    setSaveMessage(null);

    let parsedConfig: Record<string, unknown>;
    try {
      const parsed = JSON.parse(formState.configText) as unknown;
      if (parsed === null || Array.isArray(parsed) || typeof parsed !== "object") {
        throw new Error("配置 JSON 必须是对象");
      }
      parsedConfig = parsed as Record<string, unknown>;
    } catch (error) {
      setFormError(error instanceof Error ? error.message : "配置 JSON 解析失败");
      return;
    }

    const payload = {
      name: formState.name.trim(),
      channel_type: formState.channelType,
      enabled: formState.enabled,
      config_json: parsedConfig,
    };

    if (!payload.name) {
      setFormError("目标名称不能为空");
      return;
    }

    try {
      if (isEditing && editingTargetId) {
        await updateTarget.mutateAsync({
          target_id: editingTargetId,
          ...payload,
        });
      } else {
        await createTarget.mutateAsync(payload);
      }
      setSaveMessage("目标已保存");
      resetEditor();
    } catch (error) {
      setFormError(error instanceof Error ? error.message : "保存目标失败");
    }
  }

  function applyRecordFilters(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSearchParams(buildRecordSearchParams(recordFilters));
  }

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
              <div className="action-row">
                <button className="action-link action-link-obsidian" type="button" onClick={openCreateEditor}>
                  新建目标
                </button>
              </div>
              <form className="stack-sm" onSubmit={handleSubmit}>
                <label className="stack-xs">
                  <span>目标名称</span>
                  <input
                    type="text"
                    value={formState.name}
                    onChange={(event) =>
                      setFormState((current) => ({ ...current, name: event.target.value }))
                    }
                  />
                </label>
                <label className="stack-xs">
                  <span>渠道类型</span>
                  <select
                    value={formState.channelType}
                    onChange={(event) =>
                      setFormState((current) => ({ ...current, channelType: event.target.value }))
                    }
                  >
                    <option value="wecom">wecom</option>
                    <option value="email">email</option>
                    <option value="webhook">webhook</option>
                  </select>
                </label>
                <label className="stack-xs">
                  <span>配置 JSON</span>
                  <textarea
                    rows={8}
                    value={formState.configText}
                    onChange={(event) =>
                      setFormState((current) => ({ ...current, configText: event.target.value }))
                    }
                  />
                </label>
                <label className="action-row">
                  <input
                    checked={formState.enabled}
                    type="checkbox"
                    onChange={(event) =>
                      setFormState((current) => ({ ...current, enabled: event.target.checked }))
                    }
                  />
                  <span>启用目标</span>
                </label>
                <div className="action-row">
                  <button className="action-link action-link-obsidian" disabled={isSaving} type="submit">
                    {isEditing ? "保存修改" : "创建目标"}
                  </button>
                  {isEditing ? (
                    <button className="action-link action-link-muted" type="button" onClick={resetEditor}>
                      取消编辑
                    </button>
                  ) : null}
                </div>
                {formError ? <p className="card-copy">{formError}</p> : null}
                {saveMessage ? <p className="card-copy">{saveMessage}</p> : null}
              </form>
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
                      type="button"
                      onClick={() => {
                        openEditEditor(target);
                      }}
                    >
                      编辑目标
                    </button>
                    <button
                      className="action-link action-link-muted"
                      disabled={updateTarget.isPending}
                      type="button"
                      onClick={() => {
                        setSaveMessage(null);
                        setFormError(null);
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
              <form className="stack-sm" onSubmit={applyRecordFilters}>
                <label className="stack-xs">
                  <span>场景筛选</span>
                  <select
                    aria-label="场景筛选"
                    value={recordFilters.scene_name ?? ""}
                    onChange={(event) =>
                      setRecordFilters((current) => ({
                        ...current,
                        scene_name: event.target.value || null,
                      }))
                    }
                  >
                    <option value="">全部场景</option>
                    <option value="announcement">announcement</option>
                  </select>
                </label>
                <label className="stack-xs">
                  <span>状态筛选</span>
                  <select
                    aria-label="状态筛选"
                    value={recordFilters.status ?? ""}
                    onChange={(event) =>
                      setRecordFilters((current) => ({
                        ...current,
                        status: event.target.value || null,
                      }))
                    }
                  >
                    <option value="">全部状态</option>
                    <option value="prepared">prepared</option>
                    <option value="skipped">skipped</option>
                    <option value="succeeded">succeeded</option>
                    <option value="failed">failed</option>
                  </select>
                </label>
                <label className="stack-xs">
                  <span>渠道筛选</span>
                  <select
                    aria-label="渠道筛选"
                    value={recordFilters.channel_type ?? ""}
                    onChange={(event) =>
                      setRecordFilters((current) => ({
                        ...current,
                        channel_type: event.target.value || null,
                      }))
                    }
                  >
                    <option value="">全部渠道</option>
                    <option value="wecom">wecom</option>
                    <option value="email">email</option>
                    <option value="webhook">webhook</option>
                  </select>
                </label>
                <div className="action-row">
                  <button className="action-link action-link-obsidian" type="submit">
                    应用筛选
                  </button>
                  <button
                    className="action-link action-link-muted"
                    type="button"
                    onClick={() => {
                      const clearedFilters = {
                        scene_name: null,
                        status: null,
                        channel_type: null,
                      };
                      setRecordFilters(clearedFilters);
                      setSearchParams(buildRecordSearchParams(clearedFilters));
                    }}
                  >
                    清空筛选
                  </button>
                </div>
              </form>
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

function toTargetFormState(target: DeliveryTargetView): DeliveryTargetFormState {
  return {
    name: target.name,
    channelType: target.channel_type,
    enabled: target.enabled,
    configText: JSON.stringify(target.config_json ?? target.config_summary ?? {}, null, 2),
  };
}

function getRecordFiltersFromSearchParams(searchParams: URLSearchParams): DeliveryRecordFilters {
  return {
    scene_name: searchParams.get("scene_name"),
    status: searchParams.get("status"),
    channel_type: searchParams.get("channel_type"),
  };
}

function buildRecordSearchParams(filters: DeliveryRecordFilters): URLSearchParams {
  const nextSearchParams = new URLSearchParams({ tab: "records" });
  if (filters.scene_name) {
    nextSearchParams.set("scene_name", filters.scene_name);
  }
  if (filters.status) {
    nextSearchParams.set("status", filters.status);
  }
  if (filters.channel_type) {
    nextSearchParams.set("channel_type", filters.channel_type);
  }
  return nextSearchParams;
}
